include(CompileFail)

# 위치 타입(ADR 0007, invariant 15)
pa_add_compile_fail(offset_mix_compare offset_mix_compare.cpp
  "(invalid operands|no match for).*Codepoint")
pa_add_compile_fail(offset_from_size_t offset_from_size_t.cpp
  "conversion from [^ ]*int[^ ]* to[^\n]*Utf8Byte")
pa_add_compile_fail(byte_span_from_codepoint byte_span_from_codepoint.cpp
  "(no viable conversion|cannot convert)[^\n]*Codepoint")
pa_add_compile_fail(byte_span_direct byte_span_direct.cpp
  "ByteSpan[^\n]*private|private[^\n]*ByteSpan")
