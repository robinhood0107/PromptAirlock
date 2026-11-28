#!/bin/sh
set -eu

app=/opt/prompt-airlock/bin/prompt-airlock
source_dir=/run/prompt-airlock
data_dir=/var/lib/prompt-airlock
ready_marker=$data_dir/.runtime-seeded
seed_marker=$data_dir/.runtime-seeding

if [ "${1:-}" != "serve" ]; then
  exec "$app" "$@"
fi

umask 077

secure_runtime() {
  chmod 600 "$data_dir/config.json"
  chmod 700 "$data_dir/certs" "$data_dir/secrets"
  chmod 700 "$data_dir/audit"
  find "$data_dir/certs" -type f -name '*.key' -exec chmod 600 {} +
  find "$data_dir/secrets" -type f -exec chmod 600 {} +
}

seed_runtime() {
  : > "$seed_marker"
  mkdir -p "$data_dir/certs" "$data_dir/secrets" "$data_dir/audit"
  install -m 0600 "$source_dir/config.json" "$data_dir/config.json"
  cp -a "$source_dir/certs/." "$data_dir/certs/"
  cp -a "$source_dir/secrets/." "$data_dir/secrets/"
  secure_runtime
  if ! "$app" check "$data_dir/config.json" >/dev/null 2>&1; then
    printf '%s\n' 'runtime initialization check failed' >&2
    return 1
  fi
  : > "$ready_marker.tmp"
  mv "$ready_marker.tmp" "$ready_marker"
  rm -f "$seed_marker"
}

if [ -f "$ready_marker" ]; then
  secure_runtime
  if ! "$app" check "$data_dir/config.json" >/dev/null 2>&1; then
    printf '%s\n' 'runtime check failed' >&2
    exit 1
  fi
elif [ -f "$seed_marker" ]; then
  rm -rf "$data_dir/certs" "$data_dir/secrets"
  rm -f "$data_dir/config.json"
  seed_runtime
elif [ -f "$data_dir/config.json" ]; then
  secure_runtime
  if ! "$app" check "$data_dir/config.json" >/dev/null 2>&1; then
    printf '%s\n' 'existing runtime check failed' >&2
    exit 1
  fi
  : > "$ready_marker.tmp"
  mv "$ready_marker.tmp" "$ready_marker"
else
  seed_runtime
fi

exec "$app" serve "$data_dir/config.json"
