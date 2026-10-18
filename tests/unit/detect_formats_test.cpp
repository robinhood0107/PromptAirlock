// 형식 탐지기 표 시험. 값은 모두 구조로 만든 합성 값이다.
// 양성: 그 종류로, 기대한 원문 구간이 탐지된다. 음성: 그 종류로는 아무것도 탐지되지 않는다.
#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
using pc::EntityType;

namespace {

struct Case {
    std::string_view text;
    EntityType type;
    std::string_view expected;  // 양성일 때 탐지 구간의 원문. 비면 음성.
};

const pd::Detectors& detectors() {
    static const auto d = *pd::Detectors::make(std::vector<std::string_view>{"가상기관"});
    return d;
}

std::vector<std::string> found(std::string_view text, EntityType type) {
    std::vector<std::string> out;
    const auto entities = detectors().detect_segment(text, pc::SegmentIndex{0});
    EXPECT_TRUE(entities);
    for (const auto& e : *entities) {
        if (e.type() == type) {
            out.emplace_back(text.substr(e.span().begin().value(), e.span().size()));
        }
    }
    return out;
}

const std::vector<Case> positives = {
    {"연락처 010-2345-6789 입니다", EntityType::KoreanPhone, "010-2345-6789"},
    {"＋８２ １０－２３４５－６７８９", EntityType::KoreanPhone, "８２ １０－２３４５－６７８９"},
    {"대표 02-345-6789", EntityType::KoreanPhone, "02-345-6789"},
    {"031 1234 5678", EntityType::KoreanPhone, "031 1234 5678"},
    {"011-234-5678", EntityType::KoreanPhone, "011-234-5678"},
    {"0505-123-4567", EntityType::KoreanPhone, "0505-123-4567"},
    {"070.2345.6789", EntityType::KoreanPhone, "070.2345.6789"},
    {"주문 3개 010-2345-6789", EntityType::KoreanPhone, "010-2345-6789"},
    {"900101-1234567", EntityType::KoreanRrn, "900101-1234567"},
    {"9001011234567", EntityType::KoreanRrn, "9001011234567"},
    {"0​0​0229-3123456", EntityType::KoreanRrn, "0​0​0229-3123456"},  // 2000-02-29
    {"010203-7123456", EntityType::KoreanAlienRegistrationNo, "010203-7123456"},
    {"사업자 123-45-67800", EntityType::KoreanBusinessNo, "123-45-67800"},
    {"카드 4111 1111 1111 1111", EntityType::CardNumber, "4111 1111 1111 1111"},
    {"여권 M12345678", EntityType::KoreanPassportNo, "M12345678"},
    {"여권 m123a4567.", EntityType::KoreanPassportNo, "m123a4567"},
    {"11-95-255933-61", EntityType::KoreanDriverLicenseNo, "11-95-255933-61"},
    {"서울 95-255933-61", EntityType::KoreanDriverLicenseNo, "서울 95-255933-61"},
    {"운전면허번호: 119525593361", EntityType::KoreanDriverLicenseNo, "119525593361"},
    {"메일 user1@example.invalid.", EntityType::Email, "user1@example.invalid"},
    {"서버 192.0.2.10 접속", EntityType::IpAddress, "192.0.2.10"},
    {"주소 2001:db8::1 확인", EntityType::IpAddress, "2001:db8::1"},
    {"::ffff:192.0.2.1", EntityType::IpAddress, "::ffff:192.0.2.1"},
    {"가상 기관 보고서", EntityType::InternalTerm, "가상 기관"},
};

const std::vector<Case> negatives = {
    {"010-0234-5678", EntityType::KoreanPhone, {}},           // 010 국번 첫 자리는 2~9
    {"1,234,567원", EntityType::KoreanPhone, {}},
    {"A9001011234567", EntityType::KoreanRrn, {}},            // 영문에 붙은 숫자
    {"901301-1234567", EntityType::KoreanRrn, {}},            // 13월
    {"010229-3123456", EntityType::KoreanRrn, {}},            // 2001-02-29 는 없는 날
    {"900101-9234567", EntityType::KoreanRrn, {}},            // 성별 자리 9
    {"900101-9234567", EntityType::KoreanAlienRegistrationNo, {}},  // 성별 자리 9
    {"123-45-67801", EntityType::KoreanBusinessNo, {}},       // 검증 자리 틀림
    {"4111 1111 1111 1112", EntityType::CardNumber, {}},      // Luhn 틀림
    {"X12345678", EntityType::KoreanPassportNo, {}},          // 종류 문자 아님
    {"M1234567890", EntityType::KoreanPassportNo, {}},        // 길이
    {"기록 202610181230", EntityType::KoreanDriverLicenseNo, {}},  // "면허" 없이 붙여 쓴 12자리
    {"99-95-255933-61", EntityType::KoreanDriverLicenseNo, {}},    // 지역 번호 범위 밖
    {"user@localhost", EntityType::Email, {}},
    {"버전 1.2.3.4.5", EntityType::IpAddress, {}},
    {"v1.2.3.4", EntityType::IpAddress, {}},
    {"256.1.1.1", EntityType::IpAddress, {}},
    {"12:30:45", EntityType::IpAddress, {}},
    {"가상 회사", EntityType::InternalTerm, {}},
};

}  // namespace

TEST(DetectFormats, Positives) {
    for (const auto& c : positives) {
        const auto hits = found(c.text, c.type);
        EXPECT_NE(std::ranges::find(hits, std::string(c.expected)), hits.end())
            << "type=" << pc::entity_type_name(c.type) << " case=" << (&c - positives.data());
    }
}

TEST(DetectFormats, Negatives) {
    for (const auto& c : negatives) {
        EXPECT_TRUE(found(c.text, c.type).empty())
            << "type=" << pc::entity_type_name(c.type) << " case=" << (&c - negatives.data());
    }
}

TEST(DetectFormats, InternalTermsAreValidated) {
    EXPECT_EQ(pd::Detectors::make(std::vector<std::string_view>{"  "}).error(), pc::InputError::EmptyContent);
    EXPECT_EQ(pd::Detectors::make(std::vector<std::string_view>{"\xFF"}).error(), pc::InputError::InvalidUtf8);
}

TEST(DetectFormats, StopsAfterEntityLimit) {
    // 탐지 결과가 한도를 넘으면 한도 + 1 개에서 멈춘다(check_policy 가 거절한다).
    std::string text;
    for (std::size_t i = 0; i < pc::max_entities + 10; ++i) {
        text += "192.0.2.1 ";
    }
    const auto entities = detectors().detect_segment(text, pc::SegmentIndex{0});
    ASSERT_TRUE(entities);
    EXPECT_EQ(entities->size(), pc::max_entities + 1);
}
