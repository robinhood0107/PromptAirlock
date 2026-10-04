//! 자원 한도와 timeout. 한도 초과는 typed error 로 끝난다(spec §37).

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct VaultLimits {
    pub max_scopes: usize,
    pub max_mappings_per_scope: usize,
    pub max_value_bytes: usize,
    pub max_ttl: Duration,
}

impl Default for VaultLimits {
    fn default() -> Self {
        Self {
            max_scopes: 4096,
            max_mappings_per_scope: 4096,
            max_value_bytes: 4096,
            max_ttl: Duration::from_secs(3600),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActorConfig {
    /// 명령 큐 깊이. 가득 차면 Overloaded 로 즉시 거절한다.
    pub queue_capacity: usize,
    /// 만료 scope 주기 정리 간격.
    pub sweep_interval: Duration,
}

impl Default for ActorConfig {
    fn default() -> Self {
        Self { queue_capacity: 1024, sweep_interval: Duration::from_secs(1) }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub max_frame_bytes: usize,
    pub hello_timeout: Duration,
    pub idle_timeout: Duration,
    pub frame_body_timeout: Duration,
    pub write_timeout: Duration,
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: 64 * 1024,
            hello_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(300),
            frame_body_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            max_connections: 64,
        }
    }
}
