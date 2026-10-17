// 연구 빌드(PA_CORE_RESEARCH)가 아니면 연구용 열쇠를 만드는 함수가 보이지 않는다.
#if PA_CF_OK
#define PA_CORE_RESEARCH 1
#endif
#include "prompt_airlock/core/research.hpp"

namespace pc = prompt_airlock::core;

void probe() { (void)pc::make_research_only(); }
