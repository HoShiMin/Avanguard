#pragma once

/*
    Depends on:
    - string
    - vector (optional)
    - set (optional)
    - winternl.h (optional)
*/

namespace StringsAPI {

#ifdef _WINTERNL_
    std::string AnsiStringToString(PCANSI_STRING AnsiString);
    std::wstring UnicodeStringToString(PCUNICODE_STRING UnicodeString);
#endif

    std::string LowerCase(__in std::string String);
    std::wstring LowerCase(__in std::wstring String);
    void LowerCaseRef(__inout std::string& String);
    void LowerCaseRef(__inout std::wstring& String);

    std::string UpperCase(__in std::string String);
    std::wstring UpperCase(__in std::wstring String);
    void UpperCaseRef(__inout std::string& String);
    void UpperCaseRef(__inout std::wstring& String);

    bool StartsWith(const std::string& String, const std::string& Beginning);
    bool StartsWith(const std::wstring& String, const std::wstring& Beginning);

    bool EndsWith(const std::string& String, const std::string& Ending);
    bool EndsWith(const std::wstring& String, const std::wstring& Ending);

    std::string FillLeft(const std::string& String, unsigned char Length, char Filler);
    std::wstring FillLeft(const std::wstring& String, unsigned char Length, wchar_t Filler);
    std::string FillRight(const std::string& String, unsigned char Length, char Filler);
    std::wstring FillRight(const std::wstring& String, unsigned char Length, wchar_t Filler);

    std::wstring AnsiToWide(const std::string& Wide);
    std::string WideToAnsi(const std::wstring& Ansi);

    std::string IntToAnsi(int Value, int Radix = 10);
    std::string Int64ToAnsi(long long Value, int Radix = 10);
    std::string UInt64ToAnsi(unsigned long long Value, int Radix = 10);
    std::wstring IntToWide(int Value, int Radix = 10);
    std::wstring Int64ToWide(long long Value, int Radix = 10);
    std::wstring UInt64ToWide(unsigned long long Value, int Radix = 10);

    inline std::string IntToAnsiHex(int Value) { return IntToAnsi(Value, 16); }
    inline std::string Int64ToAnsiHex(__int64 Value) { return Int64ToAnsi(Value, 16); }
    inline std::string UInt64ToAnsiHex(unsigned __int64 Value) { return UInt64ToAnsi(Value, 16); }
    inline std::wstring IntToWideHex(int Value) { return IntToWide(Value, 16); }
    inline std::wstring Int64ToWideHex(__int64 Value) { return Int64ToWide(Value, 16); }
    inline std::wstring UInt64ToWideHex(unsigned __int64 Value) { return UInt64ToWide(Value, 16); }

    inline std::string IntToAnsiBin(int Value) { return IntToAnsi(Value, 2); }
    inline std::string Int64ToAnsiBin(__int64 Value) { return Int64ToAnsi(Value, 2); }
    inline std::string UInt64ToAnsiBin(unsigned __int64 Value) { return UInt64ToAnsi(Value, 2); }
    inline std::wstring IntToWideBin(int Value) { return IntToWide(Value, 2); }
    inline std::wstring Int64ToWideBin(__int64 Value) { return Int64ToWide(Value, 2); }
    inline std::wstring UInt64ToWideBin(unsigned __int64 Value) { return UInt64ToWide(Value, 2); }

    template <typename T>
    inline std::string ValToAnsi(T Value) { return std::to_string(Value); }

    template <typename T>
    inline std::wstring ValToWide(T Value) { return std::to_wstring(Value); }

    template <typename T>
    inline int StrToInt(const T& Str) { return std::stoi(Str, nullptr, 0); }

    template <typename T>
    inline int StrToUInt(const T& Str) { return std::stoul(Str, nullptr, 0); }

    template <typename T>
    inline __int64 StrToInt64(const T& Str) { return std::stoll(Str, nullptr, 0); }

    template <typename T>
    inline unsigned __int64 StrToUInt64(const T& Str) { return std::stoull(Str, nullptr, 0); }

    template <typename T>
    inline int HexToInt(const T& Str) { return std::stoi(Str, nullptr, 16); }

    template <typename T>
    inline unsigned int HexToUInt(const T& Str) { return std::stoul(Str, nullptr, 16); }

    template <typename T>
    inline __int64 HexToInt64(const T& Str) { return std::stoll(Str, nullptr, 16); }

    template <typename T>
    inline unsigned __int64 HexToUInt64(const T& Str) { return std::stoull(Str, nullptr, 16); }

    template <typename T>
    inline int BinToInt(const T& Str) { return std::stoi(Str, nullptr, 2); }

    template <typename T>
    inline unsigned int BinToUInt(const T& Str) { return std::stoul(Str, nullptr, 2); }

    template <typename T>
    inline __int64 BinToInt64(const T& Str) { return std::stoll(Str, nullptr, 2); }

    template <typename T>
    inline unsigned __int64 BinToUInt64(const T& Str) { return std::stoull(Str, nullptr, 2); }

    template <typename T>
    inline float StrToFloat(const T& Str) { return std::stof(Str, nullptr); }

    template <typename T>
    inline double StrToDouble(const T& Str) { return std::stod(Str, nullptr); }

    std::string PtrToAnsi(const void* Ptr);
    std::wstring PtrToWide(const void* Ptr);

    template <typename T>
    T TrimLeft(const T& Str) {
        if (Str.empty()) return T();
        for (size_t i = 0; i < Str.length(); ++i) {
            decltype(T::value_type) c = Str[i];
            if (c != static_cast<decltype(T::value_type)>(' ') && c != static_cast<decltype(T::value_type)>('\t'))
                return Str.substr(i);
        }
        return T();
    }

    template <typename T>
    T TrimRight(const T& Str) {
        if (Str.empty()) return T();
        for (size_t i = Str.length(); i != 0; --i) {
            decltype(T::value_type) c = Str[i - 1];
            if (c != static_cast<decltype(T::value_type)>(' ') && c != static_cast<decltype(T::value_type)>('\t'))
                return Str.substr(0, i);
        }
        return T();
    }

    template <typename T>
    T Trim(const T& Str) {
        return TrimRight(TrimLeft(Str));
    }

    template <typename T>
    bool IsStrMatches(const T* Str, const T* Mask) {
        /*
            Dr.Dobb's Algorithm:
            http://www.drdobbs.com/architecture-and-design/matching-wildcards-an-empirical-way-to-t/240169123?queryText=path%2Bmatches
        */

        const T* TameText = Str;
        const T* WildText = Mask;
        const T* TameBookmark = static_cast<T*>(0x00);
        const T* WildBookmark = static_cast<T*>(0x00);

        while (true) {
            if (*WildText == static_cast<T>('*')) {
                while (*(++WildText) == static_cast<T>('*')); // "xy" matches "x**y"
                if (!*WildText) return true; // "x" matches "*"

                if (*WildText != static_cast<T>('?')) {
                    while (*TameText != *WildText) {
                        if (!(*(++TameText)))
                            return false;  // "x" doesn't match "*y*"
                    }
                }

                WildBookmark = WildText;
                TameBookmark = TameText;
            }
            else if (*TameText != *WildText && *WildText != static_cast<T>('?')) {
                if (WildBookmark) {
                    if (WildText != WildBookmark) {
                        WildText = WildBookmark;

                        if (*TameText != *WildText) {
                            TameText = ++TameBookmark;
                            continue; // "xy" matches "*y"
                        }
                        else {
                            WildText++;
                        }
                    }

                    if (*TameText) {
                        TameText++;
                        continue; // "mississippi" matches "*sip*"
                    }
                }

                return false; // "xy" doesn't match "x"
            }

            TameText++;
            WildText++;

            if (!*TameText) {
                while (*WildText == static_cast<T>('*')) WildText++; // "x" matches "x*"

                if (!*WildText) return true; // "x" matches "x"
                return false; // "x" doesn't match "xy"
            }
        }
    }

    // SimpleReplaceString("a ab abc", "a", "abc") -> "abc abcb abcbc"
    template <typename T>
    unsigned int SimpleReplaceString(__inout T& Text, const T& Source, const T& Destination) {
        size_t SourceLength = Source.length();
        size_t DestinationLength = Destination.length();
        unsigned int ReplacingsCount = 0;

        for (size_t Index = 0; Index = Text.find(Source, Index), Index != T::npos;) {
            Text.replace(Index, SourceLength, Destination);
            Index += DestinationLength;
            ++ReplacingsCount;
        }

        return ReplacingsCount;
    }

    // SelectiveReplaceString("a ab abc", "a", "abc") -> "abc abcb abc"
    template <typename T>
    unsigned int SelectiveReplaceString(__inout T& Text, const T& Source, const T& Destination) {
        size_t TextLength = Text.length();
        size_t SourceLength = Source.length();
        size_t DestinationLength = Destination.length();
        unsigned int ReplacingsCount = 0;

        T Environment(DestinationLength, NULL);
        decltype(T::value_type)* EnvironmentPtr = &Environment[0];

        for (size_t Index = 0; Index = Text.find(Source, Index), Index != T::npos;) {
            if (DestinationLength <= TextLength - Index) {
                memcpy(EnvironmentPtr, &Text[Index], DestinationLength * sizeof(decltype(T::value_type)));

                if (Environment == Destination) {
                    Index += DestinationLength;
                    continue;
                }
            }
            Text.replace(Index, SourceLength, Destination);
            Index += DestinationLength;
            TextLength = Text.length();
            ++ReplacingsCount;
        }

        return ReplacingsCount;
    };

    template <typename T>
    T ReplaceString(const T& Text, const T& Source, const T& Destination, bool Selective = false) {
        T Result(Text);
        if (Selective)
            SelectiveReplaceString(Result, Source, Destination);
        else
            SimpleReplaceString(Result, Source, Destination);
        return Result;
    }

    template <typename T>
    T FixWin32PathSlashes(const T& String) {
        static const decltype(T::value_type) ForwardSlash[] = { '/', NULL };
        static const decltype(T::value_type) BackwardSlash[] = { '\\', NULL };
        static const decltype(T::value_type) DoubleBackwardSlashes[] = { '\\', '\\', NULL };

        T Result(String);

        SimpleReplaceString(Result, T(ForwardSlash), T(BackwardSlash));
        while (SimpleReplaceString(Result, T(DoubleBackwardSlashes), T(BackwardSlash)));
        return Result;
    }

    template <typename T>
    T FixUnixPathSlashes(const T& String) {
        static const decltype(T::value_type) ForwardSlash[] = { '/', NULL };
        static const decltype(T::value_type) BackwardSlash[] = { '\\', NULL };
        static const decltype(T::value_type) DoubleForwardSlashes[] = { '/', '/', NULL };

        T Result(String);

        SimpleReplaceString(Result, T(BackwardSlash), T(ForwardSlash));
        while (SimpleReplaceString(Result, T(DoubleForwardSlashes), T(ForwardSlash)));
        return Result;
    }

    template <typename T>
    T FixUrlSlashes(const T& String) {
        static const decltype(T::value_type) ForwardSlash[] = { '/', NULL };
        static const decltype(T::value_type) BackwardSlash[] = { '\\', NULL };
        static const decltype(T::value_type) DoubleForwardSlashes[] = { '/', '/', NULL };
        static const decltype(T::value_type) UrlBrokenSlashes[] = { ':', '/', NULL };
        static const decltype(T::value_type) UrlBaseSlashes[] = { ':', '/', '/', NULL };

        T Result(String);

        SimpleReplaceString(Result, T(BackwardSlash), T(ForwardSlash));
        while (SimpleReplaceString(Result, T(DoubleForwardSlashes), T(ForwardSlash)));
        SimpleReplaceString(Result, T(UrlBrokenSlashes), T(UrlBaseSlashes));
        return Result;
    }

#ifdef _VECTOR_
    template <typename T>
    size_t Tokenize(const T& Str, const T& Delimiters, __out std::vector<T>& Tokens) {
        Tokens.clear();

        size_t Start = Str.find_first_not_of(Delimiters);
        size_t End = Start;

        while (Start != T::npos) {
            End = Str.find(Delimiters, Start);
            Tokens.emplace_back(Str.substr(Start, End - Start));
            Start = Str.find_first_not_of(Delimiters, End);
        }
        return Tokens.size();
    }

    template <typename T>
    size_t Split(const T& Str, const T& Delimiter, __out std::vector<T>& Tokens) {
        Tokens.clear();

        size_t Start = 0;
        size_t End = Str.find(Delimiter);
        size_t DelimLength = Delimiter.length();

        while (End != T::npos) {
            Tokens.emplace_back(Str.substr(Start, End - Start));
            Start = End + DelimLength;
            End = Str.find(Delimiter, Start);
        }

        Tokens.emplace_back(Str.substr(Start));
        return Tokens.size();
    }
#endif

#ifdef _SET_
    template <typename T>
    size_t Tokenize(const T& Str, const T& Delimiters, __out std::vector<T>& Tokens) {
        Tokens.clear();

        size_t Start = Str.find_first_not_of(Delimiters);
        size_t End = Start;

        while (Start != T::npos) {
            End = Str.find(Delimiters, Start);
            Tokens.emplace(Str.substr(Start, End - Start));
            Start = Str.find_first_not_of(Delimiters, End);
        }
        return Tokens.size();
    }

    template <typename T>
    size_t Split(const T& Str, const T& Delimiter, __out std::set<T>& Tokens) {
        Tokens.clear();

        size_t Start = 0;
        size_t End = Str.find(Delimiter);
        size_t DelimLength = Delimiter.length();

        while (End != T::npos) {
            Tokens.emplace(Str.substr(Start, End - Start));
            Start = End + DelimLength;
            End = Str.find(Delimiter, Start);
        }

        Tokens.emplace(Str.substr(Start));
        return Tokens.size();
    }
#endif

}