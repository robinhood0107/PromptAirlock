// ONNX Runtime 세션(ADR 0005, 0006). ORT 헤더는 이 모듈 밖으로 나가지 않는다.
// ORT 예외는 이 경계에서 값으로 바꾼다.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <vector>

namespace prompt_airlock::ner {

// 모델 출력 [length, labels]. 한 요청의 입력 하나에 대한 결과다.
struct Logits {
    std::size_t length = 0;
    std::size_t labels = 0;
    std::vector<float> values;  // row-major

    // pos 번째 토큰의 가장 높은 label. 같은 값이면 앞선 label 이 이긴다.
    [[nodiscard]] std::size_t argmax(std::size_t pos) const noexcept;
};

enum class SessionError : std::uint8_t { Load, Run, BadOutput };

// ORT 전역 환경. 프로세스에 하나만 만들어 세션들이 함께 쓴다. 세션이 shared_ptr 로 붙잡아 세션보다 먼저 사라지지 않는다.
class OrtEnv {
    struct Impl;
    struct Key {};  // create 밖에서 생성자를 부르지 못하게 하는 열쇠

public:
    [[nodiscard]] static std::expected<std::shared_ptr<const OrtEnv>, SessionError> create();

    OrtEnv(Key, std::unique_ptr<Impl> impl) noexcept;
    OrtEnv(const OrtEnv&) = delete;
    OrtEnv& operator=(const OrtEnv&) = delete;
    ~OrtEnv();

private:
    friend class OrtSession;

    std::unique_ptr<Impl> impl_;
};

// CPU, intra/inter-op thread 1개, 순차 실행. 한 세션은 한 번에 한 스레드만 쓴다.
class OrtSession {
public:
    // onnx 는 이미 확인한 모델 바이트다. 세션이 복사해 가므로 만든 뒤 바로 버려도 된다.
    // 입력 이름이 input_ids, attention_mask, token_type_ids 가 아니면 거부한다.
    [[nodiscard]] static std::expected<OrtSession, SessionError> create(std::shared_ptr<const OrtEnv> env,
                                                                        std::span<const std::byte> onnx);

    OrtSession(OrtSession&&) noexcept;
    OrtSession& operator=(OrtSession&&) noexcept;
    ~OrtSession();

    // ids 는 [CLS] ... [SEP] 한 시퀀스(배치 1). 길이 제한은 호출자가 지킨다.
    [[nodiscard]] std::expected<Logits, SessionError> run(std::span<const std::int64_t> ids);

private:
    struct Impl;
    explicit OrtSession(std::unique_ptr<Impl> impl) noexcept;

    std::unique_ptr<Impl> impl_;
};

}  // namespace prompt_airlock::ner
