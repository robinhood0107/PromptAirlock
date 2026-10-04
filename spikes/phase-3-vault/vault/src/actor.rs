//! Single-owner actor. 전용 스레드 하나가 `VaultState` 를 소유하고, 나머지는 bounded 채널로 명령만 보낸다.
//! 큐가 가득 차면 기다리지 않고 Overloaded 로 거절한다(secure overload, spec §19).

use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::config::{ActorConfig, VaultLimits};
use crate::error::VaultError;
use crate::state::{Stats, VaultState};
use crate::token::Token;
use crate::types::{EntityLabel, ScopeId, SecretValue};

type Reply<T> = oneshot::Sender<Result<T, VaultError>>;
pub type Resolved = (EntityLabel, Zeroizing<Vec<u8>>);

pub enum Command {
    CreateScope { ttl: Duration, reply: Reply<(ScopeId, Duration)> },
    CreateToken { scope: ScopeId, label: EntityLabel, value: SecretValue, reply: Reply<Token> },
    ResolveExact { scope: ScopeId, token: String, reply: Reply<Resolved> },
    DropScope { scope: ScopeId, reply: Reply<()> },
    Stats { reply: Reply<Stats> },
    Shutdown,
}

#[derive(Clone)]
pub struct VaultHandle {
    tx: SyncSender<Command>,
}

/// 응답 대기 객체. async 와 blocking 양쪽에서 기다릴 수 있다.
pub struct Pending<T>(oneshot::Receiver<Result<T, VaultError>>);

impl<T> Pending<T> {
    pub async fn wait(self) -> Result<T, VaultError> {
        // actor 가 응답 없이 사라지면 fail closed.
        self.0.await.unwrap_or(Err(VaultError::Internal))
    }

    pub fn wait_blocking(self) -> Result<T, VaultError> {
        self.0.blocking_recv().unwrap_or(Err(VaultError::Internal))
    }
}

impl VaultHandle {
    fn submit<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> Result<Pending<T>, VaultError> {
        let (tx, rx) = oneshot::channel();
        match self.tx.try_send(make(tx)) {
            Ok(()) => Ok(Pending(rx)),
            // 거절된 명령은 여기서 drop 되며 그 안의 SecretValue 도 zeroize 된다.
            Err(TrySendError::Full(_)) => Err(VaultError::Overloaded),
            Err(TrySendError::Disconnected(_)) => Err(VaultError::ShuttingDown),
        }
    }

    pub fn create_scope(&self, ttl: Duration) -> Result<Pending<(ScopeId, Duration)>, VaultError> {
        self.submit(|reply| Command::CreateScope { ttl, reply })
    }

    pub fn create_token(
        &self,
        scope: ScopeId,
        label: EntityLabel,
        value: SecretValue,
    ) -> Result<Pending<Token>, VaultError> {
        self.submit(|reply| Command::CreateToken { scope, label, value, reply })
    }

    pub fn resolve_exact(&self, scope: ScopeId, token: String) -> Result<Pending<Resolved>, VaultError> {
        self.submit(|reply| Command::ResolveExact { scope, token, reply })
    }

    pub fn drop_scope(&self, scope: ScopeId) -> Result<Pending<()>, VaultError> {
        self.submit(|reply| Command::DropScope { scope, reply })
    }

    pub fn stats(&self) -> Result<Pending<Stats>, VaultError> {
        self.submit(|reply| Command::Stats { reply })
    }
}

pub struct ActorJoin {
    tx: SyncSender<Command>,
    join: JoinHandle<()>,
}

impl ActorJoin {
    /// 큐가 가득 차 있어도 종료 명령은 기다려서 넣는다. 종료 후 모든 scope 가 drop(zeroize)된다.
    pub fn shutdown(self) {
        let _ = self.tx.send(Command::Shutdown);
        let _ = self.join.join();
    }
}

pub fn spawn<C: Clock>(limits: VaultLimits, cfg: ActorConfig, clock: C) -> std::io::Result<(VaultHandle, ActorJoin)> {
    let (tx, rx) = mpsc::sync_channel::<Command>(cfg.queue_capacity.max(1));
    let sweep_interval = cfg.sweep_interval;
    let join = thread::Builder::new().name("vault-actor".into()).spawn(move || {
        let mut state = VaultState::new(limits, clock);
        let mut last_sweep = Instant::now();
        loop {
            match rx.recv_timeout(sweep_interval) {
                Ok(Command::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
                Ok(cmd) => handle(&mut state, cmd),
                Err(RecvTimeoutError::Timeout) => {}
            }
            // 부하가 계속 있어도 주기 정리가 밀리지 않게 한다.
            if last_sweep.elapsed() >= sweep_interval {
                state.sweep();
                last_sweep = Instant::now();
            }
        }
        // state 가 여기서 drop 되며 남은 원문이 zeroize 된다.
    })?;
    Ok((VaultHandle { tx: tx.clone() }, ActorJoin { tx, join }))
}

fn handle<C: Clock>(state: &mut VaultState<C>, cmd: Command) {
    // 응답 수신자가 이미 사라졌으면 send 가 값을 돌려주고, 그 값은 즉시 drop(zeroize)된다.
    match cmd {
        Command::CreateScope { ttl, reply } => {
            let _ = reply.send(state.create_scope(ttl));
        }
        Command::CreateToken { scope, label, value, reply } => {
            let _ = reply.send(state.create_token(&scope, label, value));
        }
        Command::ResolveExact { scope, token, reply } => {
            let _ = reply.send(state.resolve_exact(&scope, &token));
        }
        Command::DropScope { scope, reply } => {
            let _ = reply.send(state.drop_scope(&scope));
        }
        Command::Stats { reply } => {
            let _ = reply.send(Ok(state.stats()));
        }
        Command::Shutdown => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{ManualClock, SystemClock};
    use std::collections::HashMap;

    fn l(s: &str) -> EntityLabel {
        EntityLabel::parse(s).unwrap()
    }

    #[test]
    fn overload_is_typed_and_immediate() {
        // actor 없이 채널만 만들어 큐가 찬 상태를 결정적으로 재현한다.
        let (tx, _rx) = mpsc::sync_channel::<Command>(2);
        let h = VaultHandle { tx };
        let _p1 = h.create_scope(Duration::from_secs(1)).unwrap();
        let _p2 = h.create_scope(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        let err = h
            .create_token(ScopeId::generate().unwrap(), l("P"), SecretValue::from_vec(b"x".to_vec()))
            .err();
        assert_eq!(err, Some(VaultError::Overloaded));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn dead_actor_is_fail_closed() {
        let (tx, rx) = mpsc::sync_channel::<Command>(4);
        let h = VaultHandle { tx };
        let pending = h.create_scope(Duration::from_secs(1)).unwrap();
        // 응답하지 않고 명령을 버린다 → Internal
        drop(rx.recv().unwrap());
        assert_eq!(pending.wait_blocking().unwrap_err(), VaultError::Internal);
        drop(rx);
        assert_eq!(h.create_scope(Duration::from_secs(1)).err(), Some(VaultError::ShuttingDown));
    }

    #[test]
    fn periodic_sweep_with_manual_clock() {
        let clock = ManualClock::new();
        let cfg = ActorConfig { queue_capacity: 16, sweep_interval: Duration::from_millis(5) };
        let (h, join) = spawn(VaultLimits::default(), cfg, clock.clone()).unwrap();
        let (s, _) = h.create_scope(Duration::from_secs(10)).unwrap().wait_blocking().unwrap();
        h.create_token(s, l("P"), SecretValue::from_vec(b"v".to_vec())).unwrap().wait_blocking().unwrap();
        clock.advance(Duration::from_secs(11));
        // 조회 없이도 주기 정리로 사라져야 한다. 정리 주기(5ms)의 여러 배까지 상태를 확인한다.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let st = h.stats().unwrap().wait_blocking().unwrap();
            if st.scopes == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "sweep 이 동작하지 않음");
            thread::yield_now();
        }
        join.shutdown();
    }

    #[test]
    fn concurrent_scopes_no_cross_talk() {
        let (h, join) = spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let h = h.clone();
                thread::spawn(move || {
                    let (s, _) = h.create_scope(Duration::from_secs(60)).unwrap().wait_blocking().unwrap();
                    let mut toks = HashMap::new();
                    for i in 0..300 {
                        let val = format!("t{t}-synthetic-{}", i % 150);
                        let pending = loop {
                            match h.create_token(s, l("P"), SecretValue::from_vec(val.clone().into_bytes())) {
                                Ok(p) => break p,
                                Err(VaultError::Overloaded) => thread::yield_now(),
                                Err(e) => panic!("{e:?}"),
                            }
                        };
                        let tok = pending.wait_blocking().unwrap();
                        if let Some(prev) = toks.insert(val.clone(), tok.clone()) {
                            assert_eq!(prev, tok);
                        }
                    }
                    for (val, tok) in &toks {
                        let (_, got) = h.resolve_exact(s, tok.as_str().to_owned()).unwrap().wait_blocking().unwrap();
                        assert_eq!(&got[..], val.as_bytes());
                    }
                    (s, toks)
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        // 다른 스레드 scope 의 token 은 내 scope 에서 복원되지 않는다
        for (i, (s, _)) in results.iter().enumerate() {
            let (_, other) = &results[(i + 1) % results.len()];
            for tok in other.values().take(20) {
                let err = h.resolve_exact(*s, tok.as_str().to_owned()).unwrap().wait_blocking().unwrap_err();
                assert_eq!(err, VaultError::TokenNotFound);
            }
        }
        let st = h.stats().unwrap().wait_blocking().unwrap();
        assert_eq!(st, Stats { scopes: 8, mappings: 8 * 150 });
        join.shutdown();
        assert_eq!(h.create_scope(Duration::from_secs(1)).err(), Some(VaultError::ShuttingDown));
    }
}
