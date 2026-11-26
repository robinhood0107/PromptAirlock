#include "prompt_airlock/audit/log.hpp"

#include <chrono>
#include <filesystem>
#include <string>
#include <string_view>

int main(int argc, char** argv) {
    namespace audit = prompt_airlock::audit;
    using namespace std::chrono;

    if (argc < 2 || argc > 3) return 2;
    const std::filesystem::path dir(argv[1]);
    const bool partial = argc == 3 && std::string_view(argv[2]) == "partial";
    auto log = audit::AuditLog::open(dir, days(365));
    if (!log) return 3;
    const auto now = audit::Clock::now();
    if (partial) {
        if (!(*log)->append(
                "egress", "info", {{"sent", std::string(audit::recent_query_max_line_bytes + 1, 'x')}}, now) ||
            !(*log)->append("request", "info", {{"result", "pass"}, {"status", 200U}}, now)) {
            return 4;
        }
        return 0;
    }
    if (!(*log)->append("start", "info", {}, now) ||
        !(*log)->append("request", "info", {{"result", "pass"}, {"status", 200U}}, now) ||
        !(*log)->append("egress", "info", {{"sent", "SYNTHETIC_EGRESS_BODY"}}, now) ||
        !(*log)->append("request", "warn", {{"result", "reject"}, {"reason", "grade_sensitive"}}, now) ||
        !(*log)->append("request", "warn",
                        {{"result", "reject"}, {"reason", "entity_blocked"}, {"status", 400U}}, now) ||
        !(*log)->append("confirmation", "info", {{"result", "checked"}}, now) ||
        !(*log)->append("request", "warn",
                        {{"result", "reject"}, {"reason", "confirmation_required"}, {"status", 409U}}, now) ||
        !(*log)->append("egress_answer", "info", {{"answer", "SYNTHETIC_RESPONSE"}}, now) ||
        !(*log)->append("request", "warn",
                        {{"result", "reject"}, {"reason", "provider_error"}, {"status", 502U}}, now) ||
        !(*log)->append("preview", "info", {{"result", "pass"}, {"status", 200U}}, now)) {
        return 4;
    }
    return 0;
}
