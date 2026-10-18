// proto/vault_v1.proto 를 prost 로 생성한다.
// protoc 는 PROTOC 환경변수로 받는다(cmake/Vault.cmake 가 vcpkg 의 protoc 경로를 넘긴다). 없으면 빌드를 멈춘다.
fn main() {
    let proto = "../../../proto/vault_v1.proto";
    println!("cargo:rerun-if-changed={proto}");
    println!("cargo:rerun-if-env-changed=PROTOC");
    if std::env::var_os("PROTOC").is_none() {
        panic!("PROTOC 가 비어 있다. CMake(PA_WITH_VAULT=ON)로 빌드하거나 vcpkg 의 protoc 경로를 지정하라");
    }
    prost_build::Config::new().compile_protos(&[proto], &["../../../proto"]).expect("vault_v1.proto 컴파일 실패");
}
