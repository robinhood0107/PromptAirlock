# Rust Vault 를 cargo 로 빌드·시험한다. lockfile 고정(--locked), 출력은 빌드 디렉터리 안에 둔다.
find_program(PA_CARGO cargo REQUIRED)

set(PA_VAULT_MANIFEST "${PROJECT_SOURCE_DIR}/vault/Cargo.toml")
set(PA_CARGO_ENV ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${CMAKE_BINARY_DIR}/cargo")

add_custom_target(prompt_airlock_vault ALL
  COMMAND ${PA_CARGO_ENV} "${PA_CARGO}" build --release --locked --manifest-path "${PA_VAULT_MANIFEST}"
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/vault"
  USES_TERMINAL
  COMMENT "cargo build --release (Rust Vault)")

add_test(NAME vault_cargo_test
  COMMAND ${PA_CARGO_ENV} "${PA_CARGO}" test --release --locked --manifest-path "${PA_VAULT_MANIFEST}"
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/vault")
set_tests_properties(vault_cargo_test PROPERTIES TIMEOUT 600)
