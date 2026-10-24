#include "Json.hpp"
#include <charconv>
#include <cmath>
#include <stdexcept>

namespace Monitor {

namespace {

class Parser {
public:
    explicit Parser(std::string_view text) : _text(text) {}

    Json Document() {
        Json value = parseValue(0);
        skipSpace();
        if (_position != _text.size()) fail("trailing characters");
        return value;
    }

private:
    static constexpr int MaximumDepth = 64;

    [[noreturn]] void fail(const char* reason) const {
        throw std::runtime_error(std::string("invalid JSON at offset ") + std::to_string(_position) + ": " + reason);
    }

    void skipSpace() {
        while (_position < _text.size() && (_text[_position] == ' ' || _text[_position] == '\t' || _text[_position] == '\n' || _text[_position] == '\r')) ++_position;
    }

    bool consume(std::string_view word) {
        if (_text.substr(_position, word.size()) != word) return false;
        _position += word.size();
        return true;
    }

    char peek() {
        skipSpace();
        if (_position == _text.size()) fail("unexpected end");
        return _text[_position];
    }

    void expect(char character) {
        if (peek() != character) fail("unexpected character");
        ++_position;
    }

    Json parseValue(int depth) {
        if (depth >= MaximumDepth) fail("too deeply nested");
        const char next = peek();
        if (next == '{') return parseObject(depth);
        if (next == '[') return parseArray(depth);
        if (next == '"') return Json(parseString());
        if (consume("true")) return Json(true);
        if (consume("false")) return Json(false);
        if (consume("null")) return Json();
        return Json(parseNumber());
    }

    Json parseObject(int depth) {
        expect('{');
        Json object = Json::Object();
        if (peek() == '}') {
            ++_position;
            return object;
        }
        for (;;) {
            if (peek() != '"') fail("expected a member name");
            std::string name = parseString();
            expect(':');
            object.Set(std::move(name), parseValue(depth + 1));
            if (peek() == ',') {
                ++_position;
                continue;
            }
            expect('}');
            return object;
        }
    }

    Json parseArray(int depth) {
        expect('[');
        Json array = Json::Array();
        if (peek() == ']') {
            ++_position;
            return array;
        }
        for (;;) {
            array.Push(parseValue(depth + 1));
            if (peek() == ',') {
                ++_position;
                continue;
            }
            expect(']');
            return array;
        }
    }

    std::uint32_t parseHex() {
        if (_position + 4 > _text.size()) fail("short unicode escape");
        std::uint32_t value = 0;
        const auto result = std::from_chars(_text.data() + _position, _text.data() + _position + 4, value, 16);
        if (result.ec != std::errc{} || result.ptr != _text.data() + _position + 4) fail("invalid unicode escape");
        _position += 4;
        return value;
    }

    static void appendUtf8(std::string& out, std::uint32_t code) {
        if (code < 0x80) {
            out += static_cast<char>(code);
        } else if (code < 0x800) {
            out += static_cast<char>(0xc0 | (code >> 6));
            out += static_cast<char>(0x80 | (code & 0x3f));
        } else if (code < 0x10000) {
            out += static_cast<char>(0xe0 | (code >> 12));
            out += static_cast<char>(0x80 | ((code >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (code & 0x3f));
        } else {
            out += static_cast<char>(0xf0 | (code >> 18));
            out += static_cast<char>(0x80 | ((code >> 12) & 0x3f));
            out += static_cast<char>(0x80 | ((code >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (code & 0x3f));
        }
    }

    std::string parseString() {
        expect('"');
        std::string out;
        for (;;) {
            if (_position == _text.size()) fail("unterminated string");
            const char character = _text[_position++];
            if (character == '"') return out;
            if (static_cast<unsigned char>(character) < 0x20) fail("control character in string");
            if (character != '\\') {
                out += character;
                continue;
            }
            if (_position == _text.size()) fail("unterminated escape");
            const char escape = _text[_position++];
            switch (escape) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    std::uint32_t code = parseHex();
                    if (code >= 0xd800 && code < 0xdc00) {
                        if (!consume("\\u")) fail("unpaired surrogate");
                        const std::uint32_t low = parseHex();
                        if (low < 0xdc00 || low >= 0xe000) fail("unpaired surrogate");
                        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                    } else if (code >= 0xdc00 && code < 0xe000) {
                        fail("unpaired surrogate");
                    }
                    appendUtf8(out, code);
                    break;
                }
                default: fail("invalid escape");
            }
        }
    }

    double parseNumber() {
        const std::size_t start = _position;
        if (_position < _text.size() && _text[_position] == '-') ++_position;
        while (_position < _text.size() && ((_text[_position] >= '0' && _text[_position] <= '9') || _text[_position] == '.' || _text[_position] == 'e' || _text[_position] == 'E' || _text[_position] == '+' || _text[_position] == '-')) ++_position;
        double value = 0;
        const auto result = std::from_chars(_text.data() + start, _text.data() + _position, value);
        if (start == _position || result.ec != std::errc{} || result.ptr != _text.data() + _position || !std::isfinite(value)) fail("invalid value");
        return value;
    }

    std::string_view _text;
    std::size_t _position = 0;
};

void DumpString(std::string& out, const std::string& value) {
    out += '"';
    for (const char character : value) {
        switch (character) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(character) < 0x20) {
                    static constexpr char Digits[] = "0123456789abcdef";
                    out += "\\u00";
                    out += Digits[(character >> 4) & 0xf];
                    out += Digits[character & 0xf];
                } else {
                    out += character;
                }
        }
    }
    out += '"';
}

}

Json Json::Array() {
    Json value;
    value._kind = Kind::Array;
    return value;
}

Json Json::Object() {
    Json value;
    value._kind = Kind::Object;
    return value;
}

Json Json::Object(std::initializer_list<Member> members) {
    Json value = Object();
    for (const Member& member : members) value.Set(member.first, member.second);
    return value;
}

Json Json::Parse(std::string_view text) {
    return Parser(text).Document();
}

Json::Kind Json::Type() const {
    return _kind;
}

bool Json::IsNull() const {
    return _kind == Kind::Null;
}

bool Json::AsBoolean() const {
    if (_kind != Kind::Boolean) throw std::runtime_error("expected a boolean");
    return _boolean;
}

double Json::AsNumber() const {
    if (_kind != Kind::Number) throw std::runtime_error("expected a number");
    return _number;
}

const std::string& Json::AsString() const {
    if (_kind != Kind::String) throw std::runtime_error("expected a string");
    return _string;
}

const std::vector<Json>& Json::Items() const {
    if (_kind != Kind::Array) throw std::runtime_error("expected an array");
    return _items;
}

const std::vector<Json::Member>& Json::Members() const {
    if (_kind != Kind::Object) throw std::runtime_error("expected an object");
    return _members;
}

const Json* Json::Find(std::string_view name) const {
    if (_kind != Kind::Object) return nullptr;
    for (const Member& member : _members) {
        if (member.first == name) return &member.second;
    }
    return nullptr;
}

Json& Json::Push(Json value) {
    if (_kind != Kind::Array) throw std::runtime_error("Push on a JSON value that is not an array");
    _items.push_back(std::move(value));
    return _items.back();
}

Json& Json::Set(std::string name, Json value) {
    if (_kind != Kind::Object) throw std::runtime_error("Set on a JSON value that is not an object");
    for (Member& member : _members) {
        if (member.first == name) {
            member.second = std::move(value);
            return member.second;
        }
    }
    _members.emplace_back(std::move(name), std::move(value));
    return _members.back().second;
}

std::string Json::Dump() const {
    std::string out;
    dump(out);
    return out;
}

void Json::dump(std::string& out) const {
    switch (_kind) {
        case Kind::Null: out += "null"; return;
        case Kind::Boolean: out += _boolean ? "true" : "false"; return;
        case Kind::Number: {
            if (!std::isfinite(_number)) {
                out += "null";
                return;
            }
            char buffer[32];
            const auto result = std::to_chars(buffer, buffer + sizeof(buffer), _number);
            out.append(buffer, result.ptr);
            return;
        }
        case Kind::String: DumpString(out, _string); return;
        case Kind::Array:
            out += '[';
            for (std::size_t index = 0; index < _items.size(); ++index) {
                if (index != 0) out += ',';
                _items[index].dump(out);
            }
            out += ']';
            return;
        case Kind::Object:
            out += '{';
            for (std::size_t index = 0; index < _members.size(); ++index) {
                if (index != 0) out += ',';
                DumpString(out, _members[index].first);
                out += ':';
                _members[index].second.dump(out);
            }
            out += '}';
            return;
    }
}

}
