// proto/vault_v1.proto 를 prost 로 생성한다.
// protoc 는 PROTOC 환경변수로 받는다(vcpkg 가 빌드한 protoc). 없으면 빌드를 멈춘다.
fn main() {
    let proto = "../proto/vault_v1.proto";
    println!("cargo:rerun-if-changed={proto}");
    println!("cargo:rerun-if-env-changed=PROTOC");
    if std::env::var_os("PROTOC").is_none() {
        panic!(
            "PROTOC 가 비어 있다. vcpkg_installed/<triplet>/tools/protobuf/protoc 경로를 지정하라 (README 참고)"
        );
    }
    let mut config = prost_build::Config::new();
    // bytes 필드는 Vec<u8> 로 생성한다. 원문 값은 디코딩 직후 Zeroizing 으로 옮긴다.
    config
        .compile_protos(&[proto], &["../proto"])
        .expect("vault_v1.proto 컴파일 실패");
}
