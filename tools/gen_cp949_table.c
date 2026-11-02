/* CP949(UHC) → Unicode 표를 C++ 헤더로 만든다. 개발 때 Linux 에서 한 번 돌려 결과를 커밋한다(빌드·실행 때는 돌지 않는다).
 * 원천: glibc iconv 의 CP949. 두 byte 자리(앞 0x81-0xFE, 뒤 0x41-0xFE)마다 바꿔 본다.
 * 2026-11-02 대조: Windows 코드 페이지 949(.NET)와 17,048자가 같고, .NET 만 사용자 정의 영역 188자를
 * 사설 영역(U+E000-)으로 더 바꾼다. 그 188자는 뜻이 없으므로 넣지 않는다(glibc 와 같음).
 * 사용: gcc -o gen_cp949_table tools/gen_cp949_table.c && ./gen_cp949_table > src/extract/data/cp949_table.hpp
 */
#include <gnu/libc-version.h>
#include <iconv.h>
#include <stdio.h>

int main(void) {
    iconv_t cd = iconv_open("UTF-32LE", "CP949");
    if (cd == (iconv_t)-1) {
        return 1;
    }
    static unsigned table[126 * 190];
    unsigned mapped = 0;
    for (int lead = 0x81; lead <= 0xFE; ++lead) {
        for (int trail = 0x41; trail <= 0xFE; ++trail) {
            char in[2] = {(char)lead, (char)trail};
            unsigned char out[16];
            char* ip = in;
            char* op = (char*)out;
            size_t il = 2;
            size_t ol = sizeof out;
            iconv(cd, NULL, NULL, NULL, NULL);
            unsigned cp = 0;
            if (iconv(cd, &ip, &il, &op, &ol) != (size_t)-1 && il == 0 && sizeof out - ol == 4) {
                cp = out[0] | out[1] << 8 | out[2] << 16 | (unsigned)out[3] << 24;
            }
            if (cp > 0xFFFF) {
                return 2;
            }
            mapped += cp != 0;
            table[(lead - 0x81) * 190 + (trail - 0x41)] = cp;
        }
    }
    iconv_close(cd);
    printf("// 자동 생성(tools/gen_cp949_table.c, glibc %s iconv CP949). 직접 고치지 않는다.\n", gnu_get_libc_version());
    printf("// CP949 두 byte 글자 -> Unicode(BMP). 0 은 정의되지 않은 자리. 정의된 자리 %u개.\n", mapped);
    printf("#pragma once\n\n#include <array>\n#include <cstdint>\n\nnamespace prompt_airlock::extract::data {\n\n");
    printf("inline constexpr unsigned cp949_lead_first = 0x81;\ninline constexpr unsigned cp949_lead_last = 0xfe;\n");
    printf("inline constexpr unsigned cp949_trail_first = 0x41;\ninline constexpr unsigned cp949_trail_last = 0xfe;\n");
    printf("inline constexpr unsigned cp949_trail_count = cp949_trail_last - cp949_trail_first + 1;\n\n");
    printf("inline constexpr std::array<std::uint16_t, %d> cp949_table = {\n", 126 * 190);
    for (int i = 0; i < 126 * 190; ++i) {
        printf(i % 12 == 0 ? "    0x%04x," : " 0x%04x,", table[i]);
        if (i % 12 == 11 || i == 126 * 190 - 1) {
            printf("\n");
        }
    }
    printf("};\n\n}  // namespace prompt_airlock::extract::data\n");
    return 0;
}
