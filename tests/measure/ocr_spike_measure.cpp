// OCR 실험(#258, 결정 #238). PP-OCRv5 mobile 검출 + 한국어 인식 ONNX 를 CPU 로 돌리고,
// 게이트웨이와 같은 탐지기로 OCR 글자를 검사해 합성 개인정보 재현율·쪽당 시간·최대 메모리를 잰다. 실험 전용, 제품에 넣지 않는다.
//   ocr_spike_measure <모델 폴더> <쪽 폴더(pages.jsonl, *.bmp)> <out.jsonl>
#include <onnxruntime_cxx_api.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/gateway/request_json.hpp"
#include "prompt_airlock/ner/pool.hpp"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

struct Image {
    int w = 0;
    int h = 0;
    std::vector<unsigned char> bgr;  // 위에서 아래로, 행마다 w*3
};

// 24비트 BMP(아래에서 위 행 순서, 4바이트 정렬)만 읽는다.
Image read_bmp(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    const std::vector<unsigned char> b((std::istreambuf_iterator<char>(in)), {});
    const auto u32 = [&](std::size_t o) {
        return static_cast<std::uint32_t>(b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24);
    };
    Image img;
    img.w = static_cast<int>(u32(18));
    img.h = static_cast<int>(u32(22));
    const auto offset = u32(10);
    const std::size_t stride = (static_cast<std::size_t>(img.w) * 3 + 3) & ~std::size_t{3};
    img.bgr.resize(static_cast<std::size_t>(img.w) * static_cast<std::size_t>(img.h) * 3);
    for (int y = 0; y < img.h; ++y) {
        const auto* row = b.data() + offset + stride * static_cast<std::size_t>(img.h - 1 - y);
        std::copy(row, row + img.w * 3, img.bgr.begin() + static_cast<std::ptrdiff_t>(y) * img.w * 3);
    }
    return img;
}

// 쌍선형 크기 바꾸기 → CHW float, (x/255 - mean)/std.
std::vector<float> to_tensor(const Image& img, int x0, int y0, int cw, int ch, int tw, int th, const float mean[3],
                             const float sd[3]) {
    std::vector<float> t(static_cast<std::size_t>(3) * tw * th);
    for (int y = 0; y < th; ++y) {
        const float sy = std::clamp((y + 0.5f) * ch / th - 0.5f, 0.0f, ch - 1.0f);
        const int y1 = static_cast<int>(sy);
        const int y2 = std::min(y1 + 1, ch - 1);
        const float fy = sy - y1;
        for (int x = 0; x < tw; ++x) {
            const float sx = std::clamp((x + 0.5f) * cw / tw - 0.5f, 0.0f, cw - 1.0f);
            const int x1 = static_cast<int>(sx);
            const int x2 = std::min(x1 + 1, cw - 1);
            const float fx = sx - x1;
            for (int c = 0; c < 3; ++c) {
                const auto px = [&](int xx, int yy) {
                    return static_cast<float>(
                        img.bgr[(static_cast<std::size_t>(y0 + yy) * img.w + static_cast<std::size_t>(x0 + xx)) * 3 + c]);
                };
                const float v = (px(x1, y1) * (1 - fx) + px(x2, y1) * fx) * (1 - fy) +
                                (px(x1, y2) * (1 - fx) + px(x2, y2) * fx) * fy;
                t[(static_cast<std::size_t>(c) * th + y) * tw + x] = (v / 255.0f - mean[c]) / sd[c];
            }
        }
    }
    return t;
}

struct Box {
    int x0, y0, x1, y1;
};

std::vector<Ort::Value> run(Ort::Session& session, std::vector<float>& input, int tw, int th) {
    const std::int64_t shape[4] = {1, 3, th, tw};
    const auto mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
    auto value = Ort::Value::CreateTensor<float>(mem, input.data(), input.size(), shape, 4);
    Ort::AllocatorWithDefaultOptions alloc;
    const auto in_name = session.GetInputNameAllocated(0, alloc);
    const auto out_name = session.GetOutputNameAllocated(0, alloc);
    const char* in_names[] = {in_name.get()};
    const char* out_names[] = {out_name.get()};
    return session.Run(Ort::RunOptions{nullptr}, in_names, &value, 1, out_names, 1);
}

std::vector<Box> detect_boxes(Ort::Session& det, const Image& img) {
    const float scale = std::min(1.0f, 960.0f / static_cast<float>(std::max(img.w, img.h)));
    const int tw = std::max(32, static_cast<int>(std::round(img.w * scale / 32)) * 32);
    const int th = std::max(32, static_cast<int>(std::round(img.h * scale / 32)) * 32);
    const float mean[3] = {0.485f, 0.456f, 0.406f};
    const float sd[3] = {0.229f, 0.224f, 0.225f};
    auto input = to_tensor(img, 0, 0, img.w, img.h, tw, th, mean, sd);
    auto out = run(det, input, tw, th);
    const float* prob = out[0].GetTensorData<float>();
    // 0.3 넘는 칸을 4방향 연결 덩어리로 묶고, 평균 확률 0.6 이상만 글자 영역으로 둔다(DBPostProcess 설정값).
    std::vector<char> seen(static_cast<std::size_t>(tw) * th, 0);
    std::vector<Box> boxes;
    std::vector<int> stack;
    for (int start = 0; start < tw * th; ++start) {
        if (seen[start] != 0 || prob[start] <= 0.3f) continue;
        seen[start] = 1;
        stack.assign(1, start);
        Box b{tw, th, 0, 0};
        double sum = 0;
        int n = 0;
        while (!stack.empty()) {
            const int p = stack.back();
            stack.pop_back();
            const int x = p % tw;
            const int y = p / tw;
            b.x0 = std::min(b.x0, x);
            b.y0 = std::min(b.y0, y);
            b.x1 = std::max(b.x1, x);
            b.y1 = std::max(b.y1, y);
            sum += prob[p];
            ++n;
            const int next[4] = {x > 0 ? p - 1 : -1, x + 1 < tw ? p + 1 : -1, y > 0 ? p - tw : -1,
                                 y + 1 < th ? p + tw : -1};
            for (const int q : next) {
                if (q >= 0 && seen[q] == 0 && prob[q] > 0.3f) {
                    seen[q] = 1;
                    stack.push_back(q);
                }
            }
        }
        const int w = b.x1 - b.x0 + 1;
        const int h = b.y1 - b.y0 + 1;
        if (n < 3 || sum / n < 0.6 || std::min(w, h) < 3) continue;
        // unclip 1.5: 넓이*비율/둘레 만큼 바깥으로 넓힌다.
        const double d = static_cast<double>(w) * h * 1.5 / (2.0 * (w + h));
        const double ix = static_cast<double>(img.w) / tw;
        const double iy = static_cast<double>(img.h) / th;
        boxes.push_back({std::max(0, static_cast<int>((b.x0 - d) * ix)), std::max(0, static_cast<int>((b.y0 - d) * iy)),
                         std::min(img.w - 1, static_cast<int>((b.x1 + 1 + d) * ix)),
                         std::min(img.h - 1, static_cast<int>((b.y1 + 1 + d) * iy))});
    }
    return boxes;
}

std::string recognize(Ort::Session& rec, const Image& img, const Box& b, const std::vector<std::string>& dict) {
    const int cw = b.x1 - b.x0 + 1;
    const int ch = b.y1 - b.y0 + 1;
    const int th = 48;
    const int tw = std::clamp(static_cast<int>(std::ceil(48.0 * cw / ch)), 16, 3200);
    const float mean[3] = {0.5f, 0.5f, 0.5f};
    const float sd[3] = {0.5f, 0.5f, 0.5f};
    auto input = to_tensor(img, b.x0, b.y0, cw, ch, tw, th, mean, sd);
    auto out = run(rec, input, tw, th);
    const auto shape = out[0].GetTensorTypeAndShapeInfo().GetShape();  // [1, T, C]
    const float* p = out[0].GetTensorData<float>();
    // CTC 탐욕 해독: 0 은 빈칸(blank), 1.. 은 사전, 사전 밖 마지막 하나는 띄어쓰기.
    std::string text;
    std::int64_t last = 0;
    for (std::int64_t t = 0; t < shape[1]; ++t) {
        const float* row = p + t * shape[2];
        const auto k = static_cast<std::int64_t>(std::max_element(row, row + shape[2]) - row);
        if (k != 0 && k != last) {
            text += static_cast<std::size_t>(k) <= dict.size() ? dict[static_cast<std::size_t>(k) - 1] : std::string(" ");
        }
        last = k;
    }
    return text;
}

std::vector<std::string> read_dict(const fs::path& yml) {
    std::ifstream in(yml, std::ios::binary);
    std::vector<std::string> dict;
    bool on = false;
    for (std::string line; std::getline(in, line);) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.find("character_dict:") != std::string::npos) {
            on = true;
            continue;
        }
        if (!on) continue;
        if (!line.starts_with("  - ")) break;
        auto v = line.substr(4);
        if (v.size() >= 2 && (v.front() == '\'' || v.front() == '"') && v.back() == v.front()) {
            v = v.substr(1, v.size() - 2);
        }
        if (v == "''") v = "'";
        dict.push_back(v);
    }
    return dict;
}

std::vector<char> read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}

std::string alnum(std::string_view s) {
    std::string out;
    for (const char c : s) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '@' || c == '.') {
            out += c;
        }
    }
    return out;
}

// 잘못 읽은 값도 탐지됐는지 보려고 편집 거리를 잰다(2 이하를 "비슷한 값 탐지"로 센다).
std::size_t edit_distance(std::string_view a, std::string_view b) {
    std::vector<std::size_t> row(b.size() + 1);
    for (std::size_t j = 0; j <= b.size(); ++j) row[j] = j;
    for (std::size_t i = 1; i <= a.size(); ++i) {
        std::size_t diag = row[0];
        row[0] = i;
        for (std::size_t j = 1; j <= b.size(); ++j) {
            const auto up = row[j];
            row[j] = std::min({row[j] + 1, row[j - 1] + 1, diag + (a[i - 1] == b[j - 1] ? 0 : 1)});
            diag = up;
        }
    }
    return row[b.size()];
}

fs::path utf8_path(const char* s) {
    const std::string v(s);
    return fs::path(std::u8string(v.begin(), v.end()));
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 4) return 2;
    const auto models = utf8_path(argv[1]);
    const auto pages = utf8_path(argv[2]);
    Ort::Env env{ORT_LOGGING_LEVEL_ERROR, "ocr-spike"};
    Ort::SessionOptions options;
    options.SetIntraOpNumThreads(4);
    options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
    const auto det_bytes = read_file(models / "PP-OCRv5_mobile_det_onnx" / "inference.onnx");
    const auto rec_bytes = read_file(models / "korean_PP-OCRv5_mobile_rec_onnx" / "inference.onnx");
    Ort::Session det(env, det_bytes.data(), det_bytes.size(), options);
    Ort::Session rec(env, rec_bytes.data(), rec_bytes.size(), options);
    const auto dict = read_dict(models / "korean_PP-OCRv5_mobile_rec_onnx" / "inference.yml");
    const auto ner = prompt_airlock::ner::NerPool::make(PA_NER_MODEL_DIR);
    if (!ner) return 1;
    const std::string_view terms[] = {"한빛시청"};
    const auto detectors = prompt_airlock::detect::Detectors::make(terms, *ner, {});
    if (!detectors) return 1;
    std::ifstream list(pages / "pages.jsonl", std::ios::binary);
    std::ofstream out(argv[3], std::ios::binary);
    int expected = 0;
    int found = 0;
    int in_text = 0;
    int near_found = 0;
    std::vector<double> times;
    for (std::string line; std::getline(list, line);) {
        if (line.empty()) continue;
        const auto page = json::parse(line);
        const auto img = read_bmp(pages / (page["id"].get<std::string>() + ".bmp"));
        const auto start = std::chrono::steady_clock::now();
        auto boxes = detect_boxes(det, img);
        // 위에서 아래로, 같은 줄(세로 가운데가 상자 안)은 왼쪽에서 오른쪽으로.
        std::sort(boxes.begin(), boxes.end(), [](const Box& a, const Box& b) {
            const int ac = (a.y0 + a.y1) / 2;
            if (ac >= b.y0 && ac <= b.y1) return a.x0 < b.x0;
            return ac < (b.y0 + b.y1) / 2;
        });
        std::string text;
        int last_center = -1000;
        for (const auto& b : boxes) {
            const int center = (b.y0 + b.y1) / 2;
            if (!text.empty()) text += std::abs(center - last_center) < (b.y1 - b.y0) / 2 ? " " : "\n";
            text += recognize(rec, img, b, dict);
            last_center = center;
        }
        const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        times.push_back(ms);
        auto parsed = prompt_airlock::gateway::parse_request(
            json{{"messages", json::array({{{"role", "user"}, {"content", text}}})}}.dump());
        std::vector<std::string> spans;
        if (parsed) {
            const auto result = detectors->detect(parsed->document, {});
            const auto segments = parsed->document.segments();
            if (result) {
                for (const auto& e : result->entities) {
                    const auto seg = segments[e.segment().value()].text();
                    spans.push_back(alnum(seg.substr(e.span().begin().value(),
                                                     e.span().end().value() - e.span().begin().value())));
                }
            }
        }
        json hits = json::array();
        for (const auto& v : page["values"]) {
            const auto want = alnum(v["value"].get<std::string>());
            const bool hit =
                std::ranges::any_of(spans, [&](const std::string& s) { return s.find(want) != std::string::npos; });
            const bool read = alnum(text).find(want) != std::string::npos;
            const bool similar = hit || std::ranges::any_of(spans, [&](const std::string& s) {
                return edit_distance(s, want) <= 2;
            });
            ++expected;
            found += hit ? 1 : 0;
            near_found += similar ? 1 : 0;
            in_text += read ? 1 : 0;
            hits.push_back({{"type", v["type"]}, {"found", hit}, {"near", similar}, {"in_text", read}});
        }
        out << json{{"id", page["id"]}, {"ms", ms}, {"boxes", boxes.size()}, {"hits", hits}, {"text", text}}.dump(
                   -1, ' ', false, json::error_handler_t::replace)
            << '\n';
    }
    std::sort(times.begin(), times.end());
    std::size_t peak = 0;
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) peak = pmc.PeakWorkingSetSize;
#endif
    const auto at = [&](double q) {
        return times.empty() ? 0.0 : times[std::min(times.size() - 1, static_cast<std::size_t>(q * times.size()))];
    };
    std::printf("%s\n", json{{"pages", times.size()},
                             {"expected", expected},
                             {"found", found},
                             {"read_exactly", in_text},
                             {"found_or_near", near_found},
                             {"recall", expected ? static_cast<double>(found) / expected : 0.0},
                             {"p50_ms", at(0.5)},
                             {"p95_ms", at(0.95)},
                             {"max_ms", times.empty() ? 0.0 : times.back()},
                             {"peak_bytes", peak}}
                            .dump()
                            .c_str());
    return 0;
}
