// value category, move, copy elision 규칙이 실제 컴파일러에서 기대대로 동작하는지 확인한다.
#include <gtest/gtest.h>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

// 표현식의 value category 를 decltype((expr)) 규칙으로 구분한다.
template <class T> constexpr bool is_lvalue = std::is_lvalue_reference_v<T>;
template <class T> constexpr bool is_xvalue = std::is_rvalue_reference_v<T>;
template <class T> constexpr bool is_prvalue = !std::is_reference_v<T>;

struct Counter {
    int copies = 0;
    int moves = 0;
};

// 복사·이동 횟수를 세는 추적 타입.
class Tracked {
public:
    explicit Tracked(Counter& c) : counter_(&c) {}
    Tracked(const Tracked& o) : counter_(o.counter_) { ++counter_->copies; }
    Tracked(Tracked&& o) noexcept : counter_(o.counter_) { ++counter_->moves; }
    Tracked& operator=(const Tracked&) = delete;
    Tracked& operator=(Tracked&&) = delete;
    ~Tracked() = default;

private:
    Counter* counter_;
};

Tracked make_prvalue(Counter& c) { return Tracked{c}; }

Tracked make_named(Counter& c) {
    Tracked local{c};
    return local;  // NRVO 는 허용이지 보장이 아니다.
}

Tracked make_named_with_move(Counter& c) {
    Tracked local{c};
    return std::move(local);  // NOLINT 금지 규칙의 근거: NRVO 를 막고 이동을 강제한다(-Wpessimizing-move 경고 확인용).
}

// 소유가 필요한 입력은 값으로 받고 내부로 이동한다.
class Holder {
public:
    explicit Holder(Tracked t) : value_(std::move(t)) {}

private:
    Tracked value_;
};

// 민감 값의 실수 복사를 막는 move-only 타입.
class SensitiveBuffer {
public:
    explicit SensitiveBuffer(std::string v) : value_(std::move(v)) {}
    SensitiveBuffer(const SensitiveBuffer&) = delete;
    SensitiveBuffer& operator=(const SensitiveBuffer&) = delete;
    SensitiveBuffer(SensitiveBuffer&& o) noexcept : value_(std::exchange(o.value_, {})) {}
    SensitiveBuffer& operator=(SensitiveBuffer&& o) noexcept {
        value_ = std::exchange(o.value_, {});
        return *this;
    }
    ~SensitiveBuffer() = default;
    [[nodiscard]] std::size_t size() const noexcept { return value_.size(); }

private:
    std::string value_;
};

enum class Category { LvalueRef, RvalueRef };
Category which(const std::string&) { return Category::LvalueRef; }
Category which(std::string&&) { return Category::RvalueRef; }

// forwarding reference 는 호출자의 value category 를 보존한다.
template <class T>
Category forward_to_which(T&& value) {
    return which(std::forward<T>(value));
}

}  // namespace

TEST(ValueCategory, DecltypeDistinguishesCategories) {
    int x = 0;
    static_assert(is_lvalue<decltype((x))>);
    static_assert(is_xvalue<decltype((std::move(x)))>);
    static_assert(is_prvalue<decltype((x + 1))>);
    static_assert(is_lvalue<decltype(("literal"))>);  // 문자열 리터럴은 lvalue
    SUCCEED();
}

TEST(ValueCategory, ReferenceCollapsingInForwarding) {
    std::string s = "abc";
    EXPECT_EQ(forward_to_which(s), Category::LvalueRef);
    EXPECT_EQ(forward_to_which(std::string{"tmp"}), Category::RvalueRef);
    EXPECT_EQ(forward_to_which(std::move(s)), Category::RvalueRef);
    static_assert(std::is_same_v<std::string&, decltype(std::forward<std::string&>(s))>);
}

TEST(CopyElision, PrvalueReturnIsGuaranteed) {
    Counter c;
    Tracked t = make_prvalue(c);
    (void)t;
    EXPECT_EQ(c.copies, 0);
    EXPECT_EQ(c.moves, 0);
}

TEST(CopyElision, NamedReturnObserved) {
    Counter named;
    Tracked a = make_named(named);
    (void)a;
    Counter moved;
    Tracked b = make_named_with_move(moved);
    (void)b;
    // 결과는 보고서 근거로 남긴다. NRVO 가 적용되면 0, 아니면 1.
    RecordProperty("nrvo_moves", named.moves);
    RecordProperty("return_std_move_moves", moved.moves);
    EXPECT_EQ(named.copies, 0);
    EXPECT_EQ(moved.copies, 0);
    EXPECT_EQ(moved.moves, 1);
    EXPECT_LE(named.moves, moved.moves);
}

TEST(MoveSemantics, PassByValueThenMove) {
    Counter from_rvalue;
    Holder h1{Tracked{from_rvalue}};
    (void)h1;
    EXPECT_EQ(from_rvalue.copies, 0);
    EXPECT_EQ(from_rvalue.moves, 1);

    Counter from_lvalue;
    Tracked lv{from_lvalue};
    Holder h2{lv};
    (void)h2;
    EXPECT_EQ(from_lvalue.copies, 1);
    EXPECT_EQ(from_lvalue.moves, 1);
}

TEST(MoveSemantics, SensitiveBufferIsMoveOnly) {
    static_assert(!std::is_copy_constructible_v<SensitiveBuffer>);
    static_assert(!std::is_copy_assignable_v<SensitiveBuffer>);
    static_assert(std::is_nothrow_move_constructible_v<SensitiveBuffer>);

    SensitiveBuffer a{"홍길동"};
    SensitiveBuffer b = std::move(a);
    EXPECT_EQ(b.size(), std::string{"홍길동"}.size());
    // moved-from 상태는 여기서만 명시적으로 비워 두었다. 일반 코드에서는 그 값에 의존하지 않는다.
    EXPECT_EQ(a.size(), 0u);  // NOLINT(bugprone-use-after-move)

    std::vector<SensitiveBuffer> v;
    v.emplace_back("김철수");
    v.push_back(std::move(b));
    EXPECT_EQ(v.size(), 2u);
}
