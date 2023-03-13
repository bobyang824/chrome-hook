#pragma once

#include <algorithm>
#include <string>
#include <sstream>
#include <vector>

using namespace std;

namespace strutil {
    template<typename T>
    basic_string<T> to_lower(const basic_string<T>& str)
    {
        auto result = str;
        transform(result.begin(), result.end(), result.begin(), tolower);
        return result;
    }
    template<typename T>
    basic_string<T> to_lower(const T* str)
    {
        return to_lower(basic_string<T>(str));
    }

    template<typename T>
    basic_string<T> to_upper(const basic_string<T>& str)
    {
        auto result = str;
        transform(result.begin(), result.end(), result.begin(), toupper);
        return result;
    }
    template<typename T>
    basic_string<T> to_upper(const T* str)
    {
        return to_upper(basic_string<T>(str));
    }

    template<typename T>
    bool contains(const basic_string<T>& str, const basic_string<T>& substring)
    {
        return str.find(substring) != basic_string<T>::npos;
    }
    template<typename T>
    bool contains(const basic_string<T>& str, const T* substring)
    {
        return contains(str, basic_string<T>(substring));
    }
    template<typename T>
    bool contains(const T* str, const T* substring)
    {
        return contains(basic_string<T>(str), basic_string<T>(substring));
    }
    template<typename T>
    bool contains(const basic_string<T>& str, T ch)
    {
        return str.find(ch) != T::npos;
    }

    template<typename T>
    bool icontains(const basic_string<T>& str, const basic_string<T>& substring)
    {
        return contains(to_upper(str), to_upper(substring));
    }
    template<typename T>
    bool icontains(const basic_string<T>& str, const T* substring)
    {
        return contains(to_upper(str), to_upper(substring));
    }
    template<typename T>
    bool icontains(const T* str, const T* substring)
    {
        return contains(to_upper(str), to_upper(substring));
    }

    template<typename T>
    bool iequal(const basic_string<T>& str1, const basic_string<T>& str2)
    {
        return to_lower(str1) == to_lower(str2);
    }
    template<typename T>
    bool iequal(const basic_string<T>& str1, const T* str2)
    {
        return iequal(str1, basic_string<T>(str2));
    }
    template<typename T>
    bool iequal(const T* str1, const T* str2)
    {
        return iequal(basic_string<T>(str1), basic_string<T>(str2));
    }

    template<typename T>
    bool ends_with(const T& str, const T& suffix)
    {
        const auto suffix_start = str.size() - suffix.size();
        const auto result = str.find(suffix, suffix_start);
        return (result == suffix_start) && (result != T::npos);
    }
    template<typename T>
    bool ends_with(const basic_string<T>& str, const T* suffix)
    {
        return ends_with(str, basic_string<T>(suffix));
    }
    template<typename T>
    bool ends_with(const T* str, const T* suffix)
    {
        return ends_with(basic_string<T>(str), basic_string<T>(suffix));
    }

    template<typename T>
    bool iends_with(const basic_string<T>& str, const basic_string<T>& suffix)
    {
        const auto suffix_start = str.size() - suffix.size();
        const auto result = to_lower(str).find(to_lower(suffix), suffix_start);
        return (result == suffix_start) && (result != T::npos);
    }
    template<typename T>
    bool iends_with(const basic_string<T>& str, const T* suffix)
    {
        return iends_with(str, basic_string<T>(suffix));
    }
    template<typename T>
    bool iends_with(const T* str, const T* suffix)
    {
        return iends_with(basic_string<T>(str), basic_string<T>(suffix));
    }

    template<typename T>
    bool starts_with(const basic_string<T>& str, const basic_string<T>& prefix)
    {
        return str.rfind(prefix, 0) == 0;
    }
    template<typename T>
    bool starts_with(const basic_string<T>& str, const T* prefix)
    {
        return starts_with(str, basic_string<T>(prefix));
    }
    template<typename T>
    bool starts_with(const T* str, const T* prefix)
    {
        return starts_with(basic_string<T>(str), basic_string<T>(prefix));
    }

    template<typename T>
    bool istarts_with(const basic_string<T>& str, const basic_string<T>& prefix)
    {
        return to_lower(str).rfind(to_lower(prefix), 0) == 0;
    }
    template<typename T>
    bool istarts_with(const T& str, const T* prefix)
    {
        return istarts_with(str, basic_string<T>(prefix));
    }
    template<typename T>
    bool istarts_with(const T* str, const T* prefix)
    {
        return istarts_with(basic_string<T>(str), basic_string<T>(prefix));
    }

    template<typename T>
    std::vector<T> split(const T& str, const T& delim)
    {
        size_t pos_start = 0, pos_end, delim_len = delim.length();
        T token;
        std::vector<T> tokens;

        while ((pos_end = str.find(delim, pos_start)) != std::string::npos)
        {
            token = str.substr(pos_start, pos_end - pos_start);
            pos_start = pos_end + delim_len;
            tokens.push_back(token);
        }

        tokens.push_back(str.substr(pos_start));
        return tokens;
    }
    template<typename T>
    std::vector<basic_string<T>> split(const basic_string<T>& str, const T* delim)
    {
        return split(str, basic_string<T>(delim));
    }
    template<typename T>
    std::vector<T> split_any(const T& str, const T& delims)
    {
        T token;
        std::vector<T> tokens;

        size_t pos_start = 0;
        for (size_t pos_end = 0; pos_end < str.length(); ++pos_end)
        {
            if (contains(delims, str[pos_end]))
            {
                token = str.substr(pos_start, pos_end - pos_start);
                tokens.push_back(token);
                pos_start = pos_end + 1;
            }
        }
        tokens.push_back(str.substr(pos_start));
        return tokens;
    }
    template<typename T>
    basic_string<T> join(const vector<basic_string<T>>& tokens, const basic_string<T>& delim)
    {
        basic_ostringstream<T, char_traits<T>, allocator<T>> result;

        for (auto it = tokens.begin(); it != tokens.end(); ++it)
        {
            if (it != tokens.begin())
            {
                result << delim;
            }

            result << *it;
        }

        return result.str();
    }
    template<typename T>
    basic_string<T> join(const vector<basic_string<T>>& tokens, const T* delim)
    {
        return join(tokens, basic_string<T>(delim));
    }
    template<typename T>
    void drop_empty(vector<T>& tokens)
    {
        auto last = remove_if(tokens.begin(), tokens.end(), [](const T& s) { return s.empty(); });
        tokens.erase(last, tokens.end());
    }
    template<typename T>
    void drop_duplicate(T& tokens)
    {
        std::sort(tokens.begin(), tokens.end());
        auto end_unique = std::unique(tokens.begin(), tokens.end());
        tokens.erase(end_unique, tokens.end());
    }
    template<typename T>
    void trim_left(basic_string<T>& str)
    {
        str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](T ch) { return !std::isspace(ch); }));
    }
    template<typename T>
    void trim_right(basic_string<T>& str)
    {
        str.erase(std::find_if(str.rbegin(), str.rend(), [](T ch) { return !std::isspace(ch); }).base(), str.end());
    }
    template<typename T>
    void trim(basic_string<T>& str)
    {
        trim_left(str);
        trim_right(str);
    }
}