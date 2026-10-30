// 문장 판별 후보 측정(Phase 7.5-2). PA_SENTENCE_SPIKE 구성에서만 만들고 직접 실행한다.
//   sentence_candidate_measure --model e5|e5base|minilm|nli [--set final] [--threshold T] [--explain] [--dir 모델 폴더]
//                              [--split] [--gate] [--topk K]
// 후보 모델을 학습 없이(결정 #147) 돌려 문장마다 점수를 내고, 지금 규칙(NER 켬) 결과와 합쳐(OR) 막는 비율을 잰다.
//   임베딩(e5, minilm): 범주별 예시 문장과의 최대 코사인 유사도에서 업무·일반 문장과의 최대 유사도를 뺀 값.
//   문장 함의(nli): 범주별 가설을 함의할 확률의 최댓값.
// --split 은 문장을 하나씩 나눠 가장 높은 점수를 쓰고, --gate 는 개인 표지(NER 사람 또는 candidates.json 의 person_markers)가
// 있는 글에서만 판별기 결과를 쓴다(인증 정보 범주는 예외). --topk 는 범주별 상위 K 개 예시 유사도의 평균을 쓴다.
// --threshold 가 없으면 문턱값마다 표를 내고, 있으면 그 값으로 무리·범주별 표를 낸다. 원문은 출력하지 않는다.
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif

#include <onnxruntime_cxx_api.h>
#include <sentencepiece_processor.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/ner/pool.hpp"

namespace fs = std::filesystem;
namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pn = prompt_airlock::ner;
using json = nlohmann::json;

namespace {

struct Record {
    std::string id;
    std::string category;
    std::string group;
    std::string text;
    bool sensitive;
    bool rule_blocked = false;
    bool person = false;
    double score = 0.0;
    std::string predicted{};
};

json read_json(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return json::parse(in);
}

std::vector<Record> load_lines(const fs::path& path, bool ner_negatives) {
    std::ifstream in(path, std::ios::binary);
    std::vector<Record> out;
    std::string line;
    while (std::getline(in, line)) {
        const auto j = json::parse(line);
        if (ner_negatives) {
            out.push_back({j.at("id").get<std::string>(), "None", "ner-" + j.at("category").get<std::string>(), j.at("text").get<std::string>(), false});
        } else {
            out.push_back({j.at("id").get<std::string>(), j.at("category").get<std::string>(), j.at("group").get<std::string>(),
                           j.at("text").get<std::string>(), j.at("sensitive").get<bool>()});
        }
    }
    return out;
}

double peak_mb() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS c{};
    GetProcessMemoryInfo(GetCurrentProcess(), &c, sizeof c);
    return static_cast<double>(c.PeakWorkingSetSize) / (1024.0 * 1024.0);
#else
    rusage u{};
    getrusage(RUSAGE_SELF, &u);
    return static_cast<double>(u.ru_maxrss) / 1024.0;
#endif
}

double percentile(std::vector<double> v, double p) {
    if (v.empty()) {
        return 0.0;
    }
    std::ranges::sort(v);
    return v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))];
}

// XLM-R 토큰화. SentencePiece 조각 번호를 모델 어휘 번호로 옮긴다(앞의 특수 조각 4개 때문에 한 칸 밀린다).
class Tokenizer {
public:
    Tokenizer(const fs::path& spm_model, const fs::path& tokenizer_json) {
        if (!sp_.Load(spm_model.string()).ok()) {
            throw std::runtime_error("sentencepiece model");
        }
        // 모델 어휘와 조각 번호가 정말 한 칸 밀린 관계인지 시작할 때 확인한다(4 부터 2,000 까지).
        const auto vocab = read_json(tokenizer_json).at("model").at("vocab");
        for (int hf = 4; hf < 2000; ++hf) {
            if (vocab.at(hf).at(0).get<std::string>() != sp_.IdToPiece(hf - 1)) {
                throw std::runtime_error("vocabulary mismatch at " + std::to_string(hf));
            }
        }
        vocab_size_ = vocab.size();
    }
    [[nodiscard]] std::vector<std::int64_t> ids(std::string_view text) const {
        std::vector<int> pieces;
        (void)sp_.Encode(std::string(text), &pieces);
        std::vector<std::int64_t> out;
        out.reserve(pieces.size());
        for (const int p : pieces) {
            out.push_back(p == 0 ? 3 : p + 1);  // 조각 0(unk)은 모델 어휘 3
        }
        return out;
    }
    [[nodiscard]] std::size_t vocab_size() const noexcept { return vocab_size_; }

private:
    sentencepiece::SentencePieceProcessor sp_;
    std::size_t vocab_size_ = 0;
};

constexpr std::int64_t bos = 0;
constexpr std::int64_t eos = 2;
constexpr std::size_t max_tokens = 512;

class Model {
public:
    Model(Ort::Env& env, const fs::path& onnx) {
        Ort::SessionOptions options;
        options.SetIntraOpNumThreads(1);  // NER worker 와 같은 조건(스레드 1, 순차)
        options.SetInterOpNumThreads(1);
        options.SetExecutionMode(ExecutionMode::ORT_SEQUENTIAL);
        options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        #ifdef _WIN32
        session_ = std::make_unique<Ort::Session>(env, onnx.wstring().c_str(), options);
#else
        session_ = std::make_unique<Ort::Session>(env, onnx.string().c_str(), options);
#endif
        Ort::AllocatorWithDefaultOptions allocator;
        for (std::size_t i = 0; i < session_->GetInputCount(); ++i) {
            inputs_.push_back(session_->GetInputNameAllocated(i, allocator).get());
        }
        output_ = session_->GetOutputNameAllocated(0, allocator).get();
    }
    // 첫 출력과 그 모양을 돌려준다.
    std::vector<float> run(std::vector<std::int64_t> ids, std::vector<std::int64_t>& shape) {
        const auto n = static_cast<std::int64_t>(ids.size());
        const std::array<std::int64_t, 2> in_shape{1, n};
        std::vector<std::int64_t> mask(ids.size(), 1);
        std::vector<std::int64_t> types(ids.size(), 0);
        const auto memory = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        std::vector<Ort::Value> values;
        std::vector<const char*> names;
        for (const auto& name : inputs_) {
            auto& buffer = name == "input_ids" ? ids : name == "attention_mask" ? mask : types;
            values.push_back(Ort::Value::CreateTensor<std::int64_t>(memory, buffer.data(), buffer.size(), in_shape.data(), 2));
            names.push_back(name.c_str());
        }
        const char* out_name = output_.c_str();
        auto outputs = session_->Run(Ort::RunOptions{nullptr}, names.data(), values.data(), values.size(), &out_name, 1);
        const auto info = outputs.front().GetTensorTypeAndShapeInfo();
        shape = info.GetShape();
        const float* data = outputs.front().GetTensorData<float>();
        return {data, data + info.GetElementCount()};
    }

private:
    std::unique_ptr<Ort::Session> session_;
    std::vector<std::string> inputs_;
    std::string output_;
};

std::vector<std::int64_t> single(const Tokenizer& tok, std::string_view text) {
    auto ids = tok.ids(text);
    if (ids.size() > max_tokens - 2) {
        ids.resize(max_tokens - 2);
    }
    ids.insert(ids.begin(), bos);
    ids.push_back(eos);
    return ids;
}

// 문장 쌍: <s> A </s></s> B </s>
std::vector<std::int64_t> pair(const Tokenizer& tok, std::string_view a, std::string_view b) {
    auto x = tok.ids(a);
    const auto y = tok.ids(b);
    if (x.size() + y.size() > max_tokens - 4) {
        x.resize(max_tokens - 4 - y.size());
    }
    std::vector<std::int64_t> ids{bos};
    ids.insert(ids.end(), x.begin(), x.end());
    ids.push_back(eos);
    ids.push_back(eos);
    ids.insert(ids.end(), y.begin(), y.end());
    ids.push_back(eos);
    return ids;
}

// 평균 풀링 뒤 길이 1로 맞춘 문장 벡터.
std::vector<float> embed(Model& model, const Tokenizer& tok, const std::string& text) {
    std::vector<std::int64_t> shape;
    const auto out = model.run(single(tok, text), shape);
    if (shape.size() != 3) {
        throw std::runtime_error("embedding output rank");
    }
    const auto n = static_cast<std::size_t>(shape[1]);
    const auto h = static_cast<std::size_t>(shape[2]);
    std::vector<float> v(h, 0.0F);
    for (std::size_t i = 0; i < n; ++i) {
        for (std::size_t k = 0; k < h; ++k) {
            v[k] += out[i * h + k];
        }
    }
    double norm = 0.0;
    for (const float x : v) {
        norm += static_cast<double>(x) * x;
    }
    norm = std::sqrt(norm);
    for (auto& x : v) {
        x = static_cast<float>(x / norm);
    }
    return v;
}

// 마침표·물음표·느낌표·줄바꿈 뒤에서 문장을 나눈다. 빈 문장은 버린다.
std::vector<std::string> sentences(const std::string& text) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        cur.push_back(c);
        const bool end = c == '.' || c == '?' || c == '!' || c == '\n';
        if (end && (i + 1 == text.size() || text[i + 1] == ' ' || text[i + 1] == '\n')) {
            out.push_back(cur);
            cur.clear();
        }
    }
    if (cur.find_first_not_of(" \n") != std::string::npos) {
        out.push_back(cur);
    }
    return out;
}

double dot(const std::vector<float>& a, const std::vector<float>& b) {
    double s = 0.0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        s += static_cast<double>(a[i]) * b[i];
    }
    return s;
}

struct Tally {
    std::size_t total = 0;
    std::size_t blocked = 0;
};

bool must_block(const std::string& group) {
    return group == "direct" || group == "variant" || group == "split" || group == "evasive";
}

}  // namespace

int main(int argc, char** argv) {
    std::string model_name;
    bool final_set = false;
    bool explain = false;
    double fixed = std::nan("");
    bool split = false;
    bool gate = false;
    std::size_t topk = 1;
    fs::path dir;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--model" && i + 1 < argc) {
            model_name = argv[++i];
        } else if (arg == "--set" && i + 1 < argc && std::string_view(argv[i + 1]) == "final") {
            final_set = true;
            ++i;
        } else if (arg == "--threshold" && i + 1 < argc) {
            fixed = std::atof(argv[++i]);
        } else if (arg == "--explain") {
            explain = true;
        } else if (arg == "--split") {
            split = true;
        } else if (arg == "--gate") {
            gate = true;
        } else if (arg == "--topk" && i + 1 < argc) {
            topk = std::max<std::size_t>(1, std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--dir" && i + 1 < argc) {
            dir = argv[++i];
        }
    }
    const bool nli = model_name == "nli";
    if (model_name != "e5" && model_name != "e5base" && model_name != "minilm" && !nli) {
        std::printf("--model e5|e5base|minilm|nli\n");
        return 2;
    }
    if (dir.empty()) {
#ifdef _WIN32
        char* base = nullptr;
        std::size_t length = 0;
        dir = fs::path(_dupenv_s(&base, &length, "LOCALAPPDATA") == 0 && base != nullptr ? base : ".") / "prompt-airlock" / "models" /
              "phase75";
        std::free(base);
#else
        const char* base = std::getenv("HOME");
        dir = fs::path(base != nullptr ? base : ".") / ".cache" / "prompt-airlock" / "models" / "phase75";
#endif
    }
    struct Files {
        fs::path onnx, spm, tokenizer;
        std::string prefix;
    };
    const Files files = model_name == "e5"
        ? Files{dir / "intfloat_multilingual-e5-small/onnx/model.onnx", dir / "intfloat_multilingual-e5-small/onnx/sentencepiece.bpe.model",
                dir / "intfloat_multilingual-e5-small/onnx/tokenizer.json", "query: "}
        : model_name == "e5base"
        ? Files{dir / "intfloat_multilingual-e5-base/onnx/model.onnx", dir / "intfloat_multilingual-e5-base/onnx/sentencepiece.bpe.model",
                dir / "intfloat_multilingual-e5-base/onnx/tokenizer.json", "query: "}
        : model_name == "minilm"
        ? Files{dir / "sentence-transformers_paraphrase-multilingual-MiniLM-L12-v2/onnx/model.onnx",
                dir / "sentence-transformers_paraphrase-multilingual-MiniLM-L12-v2/sentencepiece.bpe.model",
                dir / "sentence-transformers_paraphrase-multilingual-MiniLM-L12-v2/tokenizer.json", ""}
        : Files{dir / "protectai_MoritzLaurer-bge-m3-zeroshot-v2.0-c-onnx/model.onnx",
                dir / "protectai_MoritzLaurer-bge-m3-zeroshot-v2.0-c-onnx/sentencepiece.bpe.model",
                dir / "protectai_MoritzLaurer-bge-m3-zeroshot-v2.0-c-onnx/tokenizer.json", ""};

    const fs::path sentence_dir = PA_SENTENCE_FIXTURE_DIR;
    auto records = load_lines(sentence_dir / (final_set ? "sentence-final.jsonl" : "sentence-dev.jsonl"), false);
    const auto negatives = load_lines(fs::path(PA_NER_FIXTURE_DIR) / (final_set ? "ner-final.jsonl" : "ner-large.jsonl"), true);
    records.insert(records.end(), negatives.begin(), negatives.end());
    const auto data = read_json(sentence_dir / "candidates.json");
    std::printf("model: %s, set: %s, records: %zu, split: %d, gate: %d, topk: %zu\n", model_name.c_str(), final_set ? "final" : "dev",
                records.size(), split ? 1 : 0, gate ? 1 : 0, topk);
    std::vector<std::string> markers;
    for (const auto& m : data.at("person_markers")) {
        markers.push_back(m.get<std::string>());
    }

    // 1. 지금 규칙(제품과 같이 NER 켬)
    {
        auto pool = pn::NerPool::make(PA_NER_MODEL_DIR);
        if (!pool) {
            std::printf("NER pool unavailable\n");
            return 2;
        }
        const auto detectors = *pd::Detectors::make({}, *pool);
        for (auto& r : records) {
            const auto found = detectors.detect_segment(r.text, pc::SegmentIndex{0});
            r.rule_blocked = !found;
            r.person = std::ranges::any_of(markers, [&](const std::string& m) { return r.text.find(m) != std::string::npos; });
            if (found) {
                for (const auto& e : *found) {
                    r.person = r.person || e.type() == pc::EntityType::Person;
                    const bool credential = e.type() == pc::EntityType::Credential;
                    const bool sensitive = e.type() == pc::EntityType::SensitivePersonalInfo;
                    if (r.sensitive ? (r.category == "Credential" ? credential : sensitive) : (credential || sensitive)) {
                        r.rule_blocked = true;
                    }
                }
            }
        }
    }

    // 2. 후보
    const double before_mb = peak_mb();
    Ort::Env env{ORT_LOGGING_LEVEL_ERROR, "phase75"};
    const auto load_start = std::chrono::steady_clock::now();
    const Tokenizer tok(files.spm, files.tokenizer);
    Model model(env, files.onnx);
    const double load_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - load_start).count();
    std::vector<std::string> categories;
    for (const auto& [name, _] : data.at("categories").items()) {
        categories.push_back(name);
    }

    std::vector<double> ms;
    std::size_t entail = 0;
    std::map<std::string, std::vector<std::vector<float>>> examples;
    std::vector<std::vector<float>> negative_vectors;
    if (nli) {
        const auto config = read_json(files.onnx.parent_path() / "config.json");
        bool found = false;
        for (const auto& [k, v] : config.at("id2label").items()) {
            if (v.get<std::string>().starts_with("entail")) {
                entail = std::stoul(k);
                found = true;
            }
        }
        if (!found) {
            std::printf("no entailment label\n");
            return 2;
        }
    } else {
        for (const auto& c : categories) {
            for (const auto& e : data.at("categories").at(c).at("examples")) {
                examples[c].push_back(embed(model, tok, files.prefix + e.get<std::string>()));
            }
        }
        for (const auto& e : data.at("negatives")) {
            negative_vectors.push_back(embed(model, tok, files.prefix + e.get<std::string>()));
        }
    }
    const auto score_one = [&](const std::string& text, std::string& predicted) {
        double best = -1e9;
        if (nli) {
            for (const auto& c : categories) {
                std::vector<std::int64_t> shape;
                const auto logits = model.run(pair(tok, text, data.at("categories").at(c).at("hypothesis").get<std::string>()), shape);
                double denom = 0.0;
                for (const float l : logits) {
                    denom += std::exp(static_cast<double>(l));
                }
                const double p = std::exp(static_cast<double>(logits.at(entail))) / denom;
                if (p > best) {
                    best = p;
                    predicted = c;
                }
            }
            return best;
        }
        const auto v = embed(model, tok, files.prefix + text);
        double neg = -1.0;
        for (const auto& n : negative_vectors) {
            neg = std::max(neg, dot(v, n));
        }
        for (const auto& c : categories) {
            std::vector<double> sims;
            for (const auto& e : examples[c]) {
                sims.push_back(dot(v, e));
            }
            std::ranges::sort(sims, std::greater<>());
            const std::size_t k = std::min(topk, sims.size());
            double mean = 0.0;
            for (std::size_t i = 0; i < k; ++i) {
                mean += sims[i];
            }
            const double s = mean / static_cast<double>(k) - neg;
            if (s > best) {
                best = s;
                predicted = c;
            }
        }
        return best;
    };
    const auto score = [&](const std::string& text, std::string& predicted) {
        if (!split) {
            return score_one(text, predicted);
        }
        double best = -1e9;
        for (const auto& s : sentences(text)) {
            std::string p;
            const double v = score_one(s, p);
            if (v > best) {
                best = v;
                predicted = p;
            }
        }
        return best;
    };
    for (auto& r : records) {
        const auto start = std::chrono::steady_clock::now();
        r.score = score(r.text, r.predicted);
        ms.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
    }
    // 256 token 요청 하나의 판별 시간: 개발용 문장을 이어 붙여 254 조각으로 맞춘다.
    std::string long_text;
    for (const auto& r : records) {
        if (tok.ids(long_text).size() >= 254) {
            break;
        }
        long_text += r.text + " ";
    }
    std::vector<double> ms256;
    for (int i = 0; i < 30; ++i) {
        std::string unused;
        const auto start = std::chrono::steady_clock::now();
        (void)score(long_text, unused);
        ms256.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
    }
    const double after_mb = peak_mb();

    // 3. 표
    const auto evaluate = [&](double t, bool print_categories) {
        std::map<std::string, Tally> by_group;
        std::map<std::string, std::map<std::string, Tally>> by_category;
        for (const auto& r : records) {
            const bool usable = !gate || r.person || r.predicted == "Credential";
            const bool blocked = r.rule_blocked || (usable && r.score >= t);
            auto& g = by_group[r.group];
            ++g.total;
            g.blocked += blocked ? 1 : 0;
            auto& c = by_category[r.category][r.group];
            ++c.total;
            c.blocked += blocked ? 1 : 0;
            if (explain && print_categories && blocked != r.sensitive) {
                std::printf("%s %s %s %s score=%.3f pred=%s rule=%d\n", blocked ? "false-block" : "miss", r.id.c_str(),
                            r.category.c_str(), r.group.c_str(), r.score, r.predicted.c_str(), r.rule_blocked ? 1 : 0);
            }
        }
        return std::pair{by_group, by_category};
    };
    const auto pct = [](const Tally& t) { return t.total == 0 ? 0.0 : 100.0 * static_cast<double>(t.blocked) / static_cast<double>(t.total); };
    const auto benign = [&](const std::map<std::string, Tally>& g) {
        Tally all;
        for (const auto& [name, t] : g) {
            if (!must_block(name)) {
                all.total += t.total;
                all.blocked += t.blocked;
            }
        }
        return all;
    };

    std::printf("load ms %.0f, peak MB before %.0f after %.0f (+%.0f)\n", load_ms, before_mb, after_mb, after_mb - before_mb);
    std::printf("classifier ms per sentence: p50 %.3f  p95 %.3f  max %.3f (n=%zu); 256-token text (%zu pieces): p50 %.3f  p95 %.3f\n",
                percentile(ms, 0.5), percentile(ms, 0.95), *std::ranges::max_element(ms), ms.size(), tok.ids(long_text).size(),
                percentile(ms256, 0.5), percentile(ms256, 0.95));
    if (std::isnan(fixed)) {
        std::vector<double> scores;
        for (const auto& r : records) {
            scores.push_back(r.score);
        }
        std::ranges::sort(scores);
        std::printf("\nrule OR (score >= t). recall%%: direct variant split evasive | false block%%: general personal ner-all benign-all\n");
        for (int q = 50; q <= 100; q += 2) {
            const double t = scores[std::min(scores.size() - 1, scores.size() * static_cast<std::size_t>(q) / 100)];
            const auto [g, _] = evaluate(t, false);
            Tally ner;
            for (const auto& [name, tl] : g) {
                if (name.starts_with("ner-")) {
                    ner.total += tl.total;
                    ner.blocked += tl.blocked;
                }
            }
            std::printf("q%3d t=%8.4f  %6.1f %6.1f %6.1f %6.1f | %6.1f %6.1f %6.1f %6.1f\n", q, t, pct(g.at("direct")), pct(g.at("variant")),
                        pct(g.at("split")), pct(g.at("evasive")), pct(g.at("general")), pct(g.at("personal")), pct(ner), pct(benign(g)));
        }
        return 0;
    }
    const auto [g, c] = evaluate(fixed, true);
    std::printf("\nthreshold %.4f (rule OR score >= t)\n%-16s %6s %8s %8s\n", fixed, "group", "n", "blocked", "rate%");
    for (const auto& [name, t] : g) {
        std::printf("%-16s %6zu %8zu %8.1f  %s\n", name.c_str(), t.total, t.blocked, pct(t), must_block(name) ? "recall" : "false block");
    }
    const auto b = benign(g);
    std::printf("%-16s %6zu %8zu %8.1f  false block\n", "benign-all", b.total, b.blocked, pct(b));
    std::printf("\nrate%% by category (blocked/n)\n%-15s", "category");
    const std::vector<std::string> groups = {"direct", "variant", "split", "evasive", "general", "personal"};
    for (const auto& name : groups) {
        std::printf(" %13s", name.c_str());
    }
    std::printf("\n");
    for (const auto& [category, row] : c) {
        if (category == "None") {
            continue;
        }
        std::printf("%-15s", category.c_str());
        for (const auto& name : groups) {
            const auto it = row.find(name);
            if (it == row.end()) {
                std::printf(" %13s", "-");
            } else {
                std::printf(" %5.1f (%2zu/%2zu)", pct(it->second), it->second.blocked, it->second.total);
            }
        }
        std::printf("\n");
    }
    return 0;
}
