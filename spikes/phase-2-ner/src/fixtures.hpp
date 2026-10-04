#pragma once
#include <expected>
#include <filesystem>
#include <string>
#include <vector>

#include "decode.hpp"

namespace prompt_airlock::ner {

struct GoldEntity {
  EntityType type;
  std::string text;
  ByteSpan bytes;
  CodepointOffset start_cp;
  CodepointOffset end_cp;
};

struct Fixture {
  std::string id;
  std::string category;
  std::string text;
  std::vector<GoldEntity> entities;
};

[[nodiscard]] std::expected<std::vector<Fixture>, std::string> load_fixtures(const std::filesystem::path& jsonl);

}  // namespace prompt_airlock::ner
