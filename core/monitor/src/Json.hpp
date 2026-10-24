#ifndef CORE_MONITOR_SRC_JSON_HPP
#define CORE_MONITOR_SRC_JSON_HPP

#include <cstdint>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Monitor {

class Json {
public:
    enum class Kind { Null, Boolean, Number, String, Array, Object };
    using Member = std::pair<std::string, Json>;

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool value) : _kind(Kind::Boolean), _boolean(value) {}
    Json(double value) : _kind(Kind::Number), _number(value) {}
    Json(int value) : Json(static_cast<double>(value)) {}
    Json(std::uint64_t value) : Json(static_cast<double>(value)) {}
    Json(const char* value) : _kind(Kind::String), _string(value) {}
    Json(std::string value) : _kind(Kind::String), _string(std::move(value)) {}
    Json(std::string_view value) : _kind(Kind::String), _string(value) {}

    static Json Array();
    static Json Object();
    static Json Object(std::initializer_list<Member> members);
    static Json Parse(std::string_view text);

    Kind Type() const;
    bool IsNull() const;
    bool AsBoolean() const;
    double AsNumber() const;
    const std::string& AsString() const;
    const std::vector<Json>& Items() const;
    const std::vector<Member>& Members() const;
    const Json* Find(std::string_view name) const;

    Json& Push(Json value);
    Json& Set(std::string name, Json value);

    std::string Dump() const;

private:
    void dump(std::string& out) const;

    Kind _kind = Kind::Null;
    bool _boolean = false;
    double _number = 0;
    std::string _string;
    std::vector<Json> _items;
    std::vector<Member> _members;
};

}

#endif
