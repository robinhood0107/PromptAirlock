#!/usr/bin/env bash
set -euo pipefail

app=$1
config=$2
directory=$(dirname -- "$config")
umask 077
first_output=$(mktemp "$directory/keys-first.XXXXXX")
first_error=$(mktemp "$directory/keys-first-error.XXXXXX")
second_output=$(mktemp "$directory/keys-second.XXXXXX")
second_error=$(mktemp "$directory/keys-second-error.XXXXXX")
failure_output=$(mktemp "$directory/keys-failure-error.XXXXXX")

cleanup() {
    rm -f -- "$first_output" "$first_error" "$second_output" "$second_error" "$failure_output"
}
trap cleanup EXIT

"$app" keys add "$config" process-a >"$first_output" 2>"$first_error" &
first_pid=$!
"$app" keys add "$config" process-b >"$second_output" 2>"$second_error" &
second_pid=$!

first_status=0
second_status=0
wait "$first_pid" || first_status=$?
wait "$second_pid" || second_status=$?
if ((first_status != 0 || second_status != 0)) || [[ -s "$first_error" || -s "$second_error" ]]; then
    printf '%s\n' 'keys_process_concurrency=failed' >&2
    exit 1
fi

mapfile -t first_lines <"$first_output"
mapfile -t second_lines <"$second_output"
if (( ${#first_lines[@]} != 1 || ${#second_lines[@]} != 1 )); then
    printf '%s\n' 'keys_process_concurrency=failed' >&2
    exit 1
fi
first_token_line=${first_lines[0]}
second_token_line=${second_lines[0]}
if [[ "$first_token_line" != 'token: '* || "$second_token_line" != 'token: '* ]]; then
    printf '%s\n' 'keys_process_concurrency=failed' >&2
    exit 1
fi
first_token=${first_token_line#token: }
second_token=${second_token_line#token: }
if [[ ! $first_token =~ ^[A-Za-z0-9_-]{43}$ || ! $second_token =~ ^[A-Za-z0-9_-]{43}$ ]]; then
    printf '%s\n' 'keys_process_concurrency=failed' >&2
    exit 1
fi
first_hash=$(printf '%s' "$first_token" | sha256sum | cut -d ' ' -f1)
second_hash=$(printf '%s' "$second_token" | sha256sum | cut -d ' ' -f1)

"$app" keys list "$config" >"$first_output" 2>"$first_error"
if [[ -s "$first_error" ]] || ! grep -Fxq 'process-a o-only' "$first_output" ||
   ! grep -Fxq 'process-b o-only' "$first_output"; then
    printf '%s\n' 'keys_process_concurrency=failed' >&2
    exit 1
fi
if ! grep -Fq "$first_hash" "$config" || ! grep -Fq "$second_hash" "$config" ||
   grep -Fq "$first_token" "$config" || grep -Fq "$second_token" "$config"; then
    printf '%s\n' 'keys_process_concurrency=failed' >&2
    exit 1
fi

output_status=0
"$app" keys add "$config" output-failure >/dev/full 2>"$failure_output" || output_status=$?
if ((output_status != 1)) || ! grep -Fq 'token_output_failed_registered' "$failure_output"; then
    printf '%s\n' 'keys_output_failure=failed' >&2
    exit 1
fi
"$app" keys list "$config" >"$first_output" 2>"$first_error"
if [[ -s "$first_error" ]] || ! grep -Fxq 'output-failure o-only' "$first_output"; then
    printf '%s\n' 'keys_output_failure_registration=failed' >&2
    exit 1
fi
"$app" keys revoke "$config" output-failure >"$first_output" 2>"$first_error"
if [[ -s "$first_error" ]] || ! grep -Fq 'keys: revoked' "$first_output"; then
    printf '%s\n' 'keys_output_failure_revoke=failed' >&2
    exit 1
fi

printf '%s\n' 'keys_process_concurrency=passed'
