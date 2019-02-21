#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <set>

#include <winternl.h>

namespace StringsAPI {

    std::string AnsiStringToString(PCANSI_STRING AnsiString) {
        if (!AnsiString
            || !AnsiString->Buffer
            || !AnsiString->Length
            || !AnsiString->MaximumLength
            || AnsiString->MaximumLength < AnsiString->Length
            ) return std::string();

        return std::string(AnsiString->Buffer, AnsiString->Length);
    }

    std::wstring UnicodeStringToString(PCUNICODE_STRING UnicodeString) {
        if (!UnicodeString
            || !UnicodeString->Buffer
            || !UnicodeString->Length
            || !UnicodeString->MaximumLength
            || UnicodeString->MaximumLength < UnicodeString->Length
            ) return std::wstring();

        return std::wstring(UnicodeString->Buffer, UnicodeString->Length / sizeof(WCHAR));
    }

    std::string LowerCase(std::string String) {
        std::transform(String.cbegin(), String.cend(), String.begin(), ::tolower);
        return String;
    }

    std::wstring LowerCase(std::wstring String) {
        std::transform(String.cbegin(), String.cend(), String.begin(), ::tolower);
        return String;
    }

    void LowerCaseRef(std::string& String) {
        std::transform(String.cbegin(), String.cend(), String.begin(), ::tolower);
    }

    void LowerCaseRef(std::wstring& String) {
        std::transform(String.cbegin(), String.cend(), String.begin(), ::tolower);
    }

    std::string UpperCase(std::string String) {
        std::transform(String.cbegin(), String.cend(), String.begin(), ::toupper);
        return String;
    }

    std::wstring UpperCase(std::wstring String) {
        std::transform(String.cbegin(), String.cend(), String.begin(), ::toupper);
        return String;
    }

    void UpperCaseRef(std::string& String) {
        std::transform(String.cbegin(), String.cend(), String.begin(), ::toupper);
    }

    void UpperCaseRef(std::wstring& String) {
        std::transform(String.cbegin(), String.cend(), String.begin(), ::toupper);
    }

    bool StartsWith(const std::string& String, const std::string& Beginning) {
        return (Beginning.size() <= String.size()) && std::equal(Beginning.begin(), Beginning.end(), String.begin());
    }

    bool StartsWith(const std::wstring& String, const std::wstring& Beginning) {
        return (Beginning.size() <= String.size()) && std::equal(Beginning.begin(), Beginning.end(), String.begin());
    }

    bool EndsWith(const std::string& String, const std::string& Ending) {
        return (Ending.size() <= String.size()) && std::equal(Ending.rbegin(), Ending.rend(), String.rbegin());
    }

    bool EndsWith(const std::wstring& String, const std::wstring& Ending) {
        return (Ending.size() <= String.size()) && std::equal(Ending.rbegin(), Ending.rend(), String.rbegin());
    }

    std::string FillLeft(const std::string& String, unsigned char Length, char Filler) {
        std::ostringstream OutputStringStream;
        OutputStringStream << std::right << std::setfill(Filler) << std::setw(Length) << String;
        return std::string(OutputStringStream.str());
    }

    std::wstring FillLeft(const std::wstring& String, unsigned char Length, wchar_t Filler) {
        std::wostringstream OutputStringStream;
        OutputStringStream << std::right << std::setfill(Filler) << std::setw(Length) << String;
        return OutputStringStream.str();
    }

    std::string FillRight(const std::string& String, unsigned char Length, char Filler) {
        std::ostringstream OutputStringStream;
        OutputStringStream << std::left << std::setfill(Filler) << std::setw(Length) << String;
        return OutputStringStream.str();
    }

    std::wstring FillRight(const std::wstring& String, unsigned char Length, wchar_t Filler) {
        std::wostringstream OutputStringStream;
        OutputStringStream << std::left << std::setfill(Filler) << std::setw(Length) << String;
        return OutputStringStream.str();
    }

    std::wstring AnsiToWide(const std::string& Ansi) {
        if (Ansi.empty()) return std::wstring();
        int BufferSize = MultiByteToWideChar(
            CP_ACP,
            MB_PRECOMPOSED,
            Ansi.c_str(),
            -1,
            NULL,
            0
        );
        if (BufferSize < 2) return std::wstring();
        std::wstring Wide(BufferSize, NULL);
        BufferSize = MultiByteToWideChar(
            CP_ACP,
            MB_PRECOMPOSED,
            Ansi.c_str(),
            -1,
            &Wide[0],
            BufferSize
        );
        if (BufferSize < 2) return std::wstring();
        Wide.resize(static_cast<size_t>(BufferSize) - 1);
        return Wide;
    }

    std::string WideToAnsi(const std::wstring& Wide) {
        if (Wide.empty()) return std::string();
        int BufferSize = WideCharToMultiByte(
            CP_ACP,
            WC_COMPOSITECHECK | WC_DISCARDNS | WC_SEPCHARS | WC_DEFAULTCHAR,
            Wide.c_str(),
            -1,
            NULL,
            0,
            NULL,
            NULL
        );
        if (BufferSize < 2) return std::string();
        std::string Ansi(BufferSize, NULL);
        BufferSize = WideCharToMultiByte(
            CP_ACP,
            WC_COMPOSITECHECK | WC_DISCARDNS | WC_SEPCHARS | WC_DEFAULTCHAR,
            Wide.c_str(),
            -1,
            &Ansi[0],
            BufferSize,
            NULL,
            NULL
        );
        if (BufferSize < 2) return std::string();
        Ansi.resize(static_cast<size_t>(BufferSize) - 1);
        return Ansi;
    }

    std::string IntToAnsi(int Value, int Radix) {
        char Buf[34];
        Buf[0] = 0x00;
        _itoa_s(Value, Buf, sizeof(Buf), Radix);
        return Buf;
    }

    std::string Int64ToAnsi(long long Value, int Radix) {
        char Buf[66];
        Buf[0] = 0x00;
        _i64toa_s(Value, Buf, sizeof(Buf), Radix);
        return Buf;
    }

    std::string UInt64ToAnsi(unsigned long long Value, int Radix) {
        char Buf[66];
        Buf[0] = 0x00;
        _ui64toa_s(Value, Buf, sizeof(Buf), Radix);
        return Buf;
    }

    std::wstring IntToWide(int Value, int Radix) {
        wchar_t Buf[34];
        Buf[0] = 0x00;
        _itow_s(Value, Buf, sizeof(Buf) / sizeof(*Buf), Radix);
        return Buf;
    }

    std::wstring Int64ToWide(long long Value, int Radix) {
        wchar_t Buf[66];
        Buf[0] = 0x00;
        _i64tow_s(Value, Buf, sizeof(Buf) / sizeof(*Buf), Radix);
        return Buf;
    }

    std::wstring UInt64ToWide(unsigned long long Value, int Radix) {
        wchar_t Buf[66];
        Buf[0] = 0x00;
        _ui64tow_s(Value, Buf, sizeof(Buf) / sizeof(*Buf), Radix);
        return Buf;
    }

    std::string PtrToAnsi(const void* Ptr) {
#ifdef _AMD64_
        return UInt64ToAnsi(reinterpret_cast<unsigned long long>(Ptr), 16);
#else
        return IntToAnsi(reinterpret_cast<int>(Ptr), 16);
#endif
    }

    std::wstring PtrToWide(const void* Ptr) {
#ifdef _AMD64_
        return UInt64ToWide(reinterpret_cast<unsigned long long>(Ptr), 16);
#else
        return IntToWide(reinterpret_cast<int>(Ptr), 16);
#endif
    }

}