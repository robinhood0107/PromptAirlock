#include "fixtures.hpp"

#include <fstream>

#include <nlohmann/json.hpp>

namespace prompt_airlock::ner {

std::expected<std::vector<Fixture>, std::string> load_fixtures(const std::filesystem::path& jsonl) {
  std::ifstream in(jsonl, std::ios::binary);
  if (!in) return std::unexpected("cannot open " + jsonl.string());
  std::vector<Fixture> out;
  std::string line;
  try {
    while (std::getline(in, line)) {
      if (line.empty()) continue;
      const auto j = nlohmann::json::parse(line);
      Fixture f{j.at("id"), j.at("category"), j.at("text"), {}};
      for (const auto& e : j.at("entities")) {
        const auto type = e.at("type").get<std::string>();
        if (type != "PERSON" && type != "ORG") return std::unexpected(f.id + ": unknown type " + type);
        f.entities.push_back(GoldEntity{
            type == "PERSON" ? EntityType::Person : EntityType::Organization, e.at("text"),
            ByteSpan{Utf8ByteOffset{e.at("start_byte").get<std::size_t>()}, Utf8ByteOffset{e.at("end_byte").get<std::size_t>()}},
            CodepointOffset{e.at("start_cp").get<std::size_t>()}, CodepointOffset{e.at("end_cp").get<std::size_t>()}});
      }
      out.push_back(std::move(f));
    }
  } catch (const nlohmann::json::exception& ex) {
    return std::unexpected(std::string("fixture parse: ") + ex.what());
  }
  return out;
}

}  // namespace prompt_airlock::ner
