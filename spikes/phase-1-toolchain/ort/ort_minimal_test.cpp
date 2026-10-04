// ONNX Runtime C++ API 최소 inference 와 예외 경계(Ort::Exception → typed error)를 확인한다.
#include <gtest/gtest.h>

#include <onnxruntime_cxx_api.h>

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace {

enum class InferenceError { ModelLoad, Run, Shape };

struct Session {
    Ort::Env env{ORT_LOGGING_LEVEL_WARNING, "pa-spike"};
    Ort::Session session{nullptr};
};

// 라이브러리 예외는 effect boundary 에서 잡아 typed error 로 바꾼다.
std::expected<Session, InferenceError> open_session(const std::filesystem::path& model) {
    try {
        Session s;
        Ort::SessionOptions opts;
        opts.SetIntraOpNumThreads(1);
        opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        s.session = Ort::Session(s.env, model.c_str(), opts);
        return s;
    } catch (const Ort::Exception&) {
        return std::unexpected(InferenceError::ModelLoad);
    }
}

std::expected<std::vector<float>, InferenceError> run_relu(Session& s, std::vector<float> input) {
    try {
        Ort::AllocatorWithDefaultOptions alloc;
        const auto in_name = s.session.GetInputNameAllocated(0, alloc);
        const auto out_name = s.session.GetOutputNameAllocated(0, alloc);
        auto shape = s.session.GetInputTypeInfo(0).GetTensorTypeAndShapeInfo().GetShape();
        std::int64_t count = 1;
        for (auto& d : shape) {
            if (d < 0) d = 1;
            count *= d;
        }
        if (count != static_cast<std::int64_t>(input.size())) return std::unexpected(InferenceError::Shape);

        const auto mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value tensor = Ort::Value::CreateTensor<float>(mem, input.data(), input.size(), shape.data(), shape.size());
        const std::array<const char*, 1> in_names{in_name.get()};
        const std::array<const char*, 1> out_names{out_name.get()};
        auto outputs = s.session.Run(Ort::RunOptions{nullptr}, in_names.data(), &tensor, 1, out_names.data(), 1);
        const float* data = outputs.front().GetTensorData<float>();
        const auto n = outputs.front().GetTensorTypeAndShapeInfo().GetElementCount();
        return std::vector<float>(data, data + n);
    } catch (const Ort::Exception&) {
        return std::unexpected(InferenceError::Run);
    }
}

std::filesystem::path model_path() { return std::filesystem::path(PA_MODEL_DIR) / "single_relu.onnx"; }

}  // namespace

TEST(OrtMinimal, ReportsVersionAndShape) {
    RecordProperty("ort_version", Ort::GetVersionString());
    auto s = open_session(model_path());
    ASSERT_TRUE(s.has_value());
    const auto shape = s->session.GetInputTypeInfo(0).GetTensorTypeAndShapeInfo().GetShape();
    std::string shape_text;
    for (auto d : shape) shape_text += std::to_string(d) + ",";
    RecordProperty("input_shape", shape_text);
    EXPECT_EQ(s->session.GetInputCount(), 1u);
    EXPECT_EQ(s->session.GetOutputCount(), 1u);
}

TEST(OrtMinimal, ReluInferenceMatchesExpected) {
    auto s = open_session(model_path());
    ASSERT_TRUE(s.has_value());
    const auto shape = s->session.GetInputTypeInfo(0).GetTensorTypeAndShapeInfo().GetShape();
    std::int64_t count = 1;
    for (auto d : shape) count *= (d < 0 ? 1 : d);
    std::vector<float> input(static_cast<std::size_t>(count));
    for (std::size_t i = 0; i < input.size(); ++i) input[i] = static_cast<float>(i) - 2.5f;

    const auto out = run_relu(*s, input);
    ASSERT_TRUE(out.has_value());
    ASSERT_EQ(out->size(), input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        EXPECT_FLOAT_EQ((*out)[i], input[i] > 0.0f ? input[i] : 0.0f);
    }
}

TEST(OrtMinimal, MissingModelBecomesTypedError) {
    const auto s = open_session(std::filesystem::path(PA_MODEL_DIR) / "does-not-exist.onnx");
    ASSERT_FALSE(s.has_value());
    EXPECT_EQ(s.error(), InferenceError::ModelLoad);
}
