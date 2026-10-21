#include "prompt_airlock/ner/session.hpp"

#include <onnxruntime_cxx_api.h>

#include <algorithm>
#include <array>
#include <exception>
#include <string>

namespace prompt_airlock::ner {

struct OrtEnv::Impl {
    Ort::Env env{ORT_LOGGING_LEVEL_ERROR, "prompt-airlock-ner"};
};

OrtEnv::OrtEnv(Key, std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
OrtEnv::~OrtEnv() = default;

std::expected<std::shared_ptr<const OrtEnv>, SessionError> OrtEnv::create() {
    try {
        return std::make_shared<const OrtEnv>(Key{}, std::make_unique<Impl>());
    } catch (const std::exception&) {
        return std::unexpected(SessionError::Load);
    }
}

struct OrtSession::Impl {
    // 선언 순서가 곧 해제 역순이다. Env 는 세션보다 오래 살아야 한다.
    std::shared_ptr<const OrtEnv> env;
    std::unique_ptr<Ort::Session> session;
    std::vector<std::string> input_names;
    std::string output_name;
};

std::size_t Logits::argmax(std::size_t pos) const noexcept {
    const auto* row = values.data() + pos * labels;
    return static_cast<std::size_t>(std::max_element(row, row + labels) - row);
}

OrtSession::OrtSession(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
OrtSession::OrtSession(OrtSession&&) noexcept = default;
OrtSession& OrtSession::operator=(OrtSession&&) noexcept = default;
OrtSession::~OrtSession() = default;

std::expected<OrtSession, SessionError> OrtSession::create(std::shared_ptr<const OrtEnv> env,
                                                           std::span<const std::byte> onnx) {
    if (!env) {
        return std::unexpected(SessionError::Load);
    }
    try {
        auto impl = std::make_unique<Impl>();
        impl->env = std::move(env);
        Ort::SessionOptions options;
        options.SetIntraOpNumThreads(1);
        options.SetInterOpNumThreads(1);
        options.SetExecutionMode(ExecutionMode::ORT_SEQUENTIAL);
        options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        impl->session = std::make_unique<Ort::Session>(impl->env->impl_->env, onnx.data(), onnx.size(), options);

        Ort::AllocatorWithDefaultOptions allocator;
        bool has_input_ids = false;
        for (std::size_t i = 0; i < impl->session->GetInputCount(); ++i) {
            auto name = std::string(impl->session->GetInputNameAllocated(i, allocator).get());
            if (name != "input_ids" && name != "attention_mask" && name != "token_type_ids") {
                return std::unexpected(SessionError::Load);  // 모르는 입력 계약은 거부
            }
            has_input_ids = has_input_ids || name == "input_ids";
            impl->input_names.push_back(std::move(name));
        }
        if (!has_input_ids || impl->session->GetOutputCount() < 1) {
            return std::unexpected(SessionError::Load);
        }
        impl->output_name = impl->session->GetOutputNameAllocated(0, allocator).get();
        return OrtSession(std::move(impl));
    } catch (const std::exception&) {
        return std::unexpected(SessionError::Load);
    }
}

std::expected<Logits, SessionError> OrtSession::run(std::span<const std::int64_t> ids) {
    try {
        const auto n = static_cast<std::int64_t>(ids.size());
        const std::array<std::int64_t, 2> shape{1, n};
        std::vector<std::int64_t> input_ids(ids.begin(), ids.end());
        std::vector<std::int64_t> mask(ids.size(), 1);
        std::vector<std::int64_t> types(ids.size(), 0);
        const auto memory = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

        std::vector<Ort::Value> values;
        std::vector<const char*> names;
        for (const auto& name : impl_->input_names) {
            auto& buffer = name == "input_ids" ? input_ids : name == "attention_mask" ? mask : types;
            values.push_back(Ort::Value::CreateTensor<std::int64_t>(memory, buffer.data(), buffer.size(),
                                                                    shape.data(), shape.size()));
            names.push_back(name.c_str());
        }
        const char* output_name = impl_->output_name.c_str();
        auto outputs = impl_->session->Run(Ort::RunOptions{nullptr}, names.data(), values.data(), values.size(),
                                           &output_name, 1);

        const auto info = outputs.front().GetTensorTypeAndShapeInfo();
        const auto out_shape = info.GetShape();
        if (info.GetElementType() != ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT || out_shape.size() != 3 ||
            out_shape[0] != 1 || out_shape[1] != n || out_shape[2] <= 0) {
            return std::unexpected(SessionError::BadOutput);
        }
        Logits logits;
        logits.length = ids.size();
        logits.labels = static_cast<std::size_t>(out_shape[2]);
        const float* data = outputs.front().GetTensorData<float>();
        logits.values.assign(data, data + logits.length * logits.labels);
        return logits;
    } catch (const std::exception&) {
        return std::unexpected(SessionError::Run);
    }
}

}  // namespace prompt_airlock::ner
