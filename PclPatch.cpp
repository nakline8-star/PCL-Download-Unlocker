#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "comdlg32.lib")

// IL_001A: ldstr             (72 8A 49 01 70)
// ldsfld  $IR3-3             (7E FD 09 00 04)
// brfalse.s +0x07            (2C 07)
// ldsfld  $IR3-3
// br.s    +0x16              (2B 16)
// ldsfld  $I                 (7E FB 09 00 04)
// ldftn   _Lambda$__R3-3     (FE 06 67 14 00 06)
// newobj   Action`1..ctor     (73 8E 05 00 0A)
// dup                       (25)
// stsfld  $IR3-3             (80 FD 09 00 04)
// ldnull                    (14)
// ldc.i4.2 (ThreadPriority)  (18)
// newobj   LoaderTask..ctor   (73 8F 05 00 0A)
// ldarg.0; ldftn _Lambda$__R3-4  (02 FE 06 1C 06 00 06)
static const uint8_t SIG1[] = {
    0x72, 0x8A, 0x49, 0x01, 0x70,
    0x7E, 0xFD, 0x09, 0x00, 0x04,
    0x2C, 0x07,
    0x7E, 0xFD, 0x09, 0x00, 0x04,
    0x2B, 0x16,
    0x7E, 0xFB, 0x09, 0x00, 0x04,
    0xFE, 0x06, 0x67, 0x14, 0x00, 0x06,
    0x73, 0x8E, 0x05, 0x00, 0x0A,
    0x25,
    0x80, 0xFD, 0x09, 0x00, 0x04,
    0x14,
    0x18,
    0x73, 0x8F, 0x05, 0x00, 0x0A,
    0x02, 0xFE, 0x06, 0x1C, 0x06, 0x00, 0x06,
};
static const char MASK1[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

//   ldsfld PCL.ModDownload::DlClientListLoader (0x0400040F)
//   nop * 43
static const uint8_t REPL1[] = {
    0x7E, 0x0F, 0x04, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
// ldarg.0
// callvirt get_CardMinecraft      (6F 71 05 00 06)
// ldc.i4.2                        (18) to ldc.i4.0 (16)
// callvirt UIElement::set_Visibility (6F 0E 01 00 0A)
// ldarg.0
// callvirt get_BtnBack            (6F 5D 05 00 06)
// ldc.i4.2                        (18)
// callvirt UIElement::set_Visibility (6F 0E 01 00 0A)
// ldarg.0; callvirt get_ImgLogo; ldc.r8  (02 6F 5F 05 00 06 23)
static const uint8_t SIG2[] = {
    0x02,
    0x6F, 0x71, 0x05, 0x00, 0x06,
    0x18,
    0x6F, 0x0E, 0x01, 0x00, 0x0A,
    0x02,
    0x6F, 0x5D, 0x05, 0x00, 0x06,
    0x18,
    0x6F, 0x0E, 0x01, 0x00, 0x0A,
    0x02, 0x6F, 0x5F, 0x05, 0x00, 0x06, 0x23,
};

static const char MASK2[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
static const size_t SIG2_PATCH_OFF = 6;
static const uint8_t SIG2_PATCH_BYTE = 0x16; // ldc.i4.0 (Visible)

static_assert(sizeof(MASK1) == sizeof(SIG1) + 1, "MASK1 length mismatch");
static_assert(sizeof(MASK2) == sizeof(SIG2) + 1, "MASK2 length mismatch");
static_assert(sizeof(REPL1) == 48, "REPL1 must replace exactly the first 48 bytes of SIG1");

static const uint8_t LDSFLD_DLLOADER[] = { 0x7E, 0x0F, 0x04, 0x00, 0x04 };

static std::vector<long> findAll(const std::vector<uint8_t>& data,
                                 const uint8_t* pat, const char* mask, size_t len)
{
    std::vector<long> hits;
    if (data.size() < len) return hits;
    const size_t n = data.size() - len;
    for (size_t i = 0; i <= n; ++i) {
        size_t j = 0;
        for (; j < len; ++j)
            if (mask[j] == 'x' && data[i + j] != pat[j]) break;
        if (j == len) hits.push_back(static_cast<long>(i));
    }
    return hits;
}

static size_t countOccurrences(const std::vector<uint8_t>& data,
                               const uint8_t* pat, size_t len)
{
    size_t cnt = 0;
    if (data.size() < len) return 0;
    const size_t n = data.size() - len;
    for (size_t i = 0; i <= n; ++i)
        if (std::memcmp(data.data() + i, pat, len) == 0) ++cnt;
    return cnt;
}

static bool readFile(const wchar_t* path, std::vector<uint8_t>& out)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 256ll * 1024 * 1024) {
        CloseHandle(h);
        return false;
    }
    out.resize(static_cast<size_t>(sz.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(h);
    return ok && read == out.size();
}

static bool writeFile(const wchar_t* path, const std::vector<uint8_t>& data)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    CloseHandle(h);
    return ok && written == data.size();
}

static std::wstring browseFile()
{
    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetConsoleWindow();
    ofn.lpstrFilter = L"PCL2 (*.exe)\0*.exe\0All File (*.*)\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Select PCL2.exe";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&ofn)) return file;
    return L"";
}

static int patchFile(const std::wstring& path, bool noBackup)
{
    std::vector<uint8_t> data;
    if (!readFile(path.c_str(), data)) {
        std::fwprintf(stderr, L"[Error] Can't read the file: %ls\n", path.c_str());
        return 2;
    }
    if (data.size() < 2 || data[0] != 'M' || data[1] != 'Z') {
        std::fwprintf(stderr, L"[Error] Not a valid PE file: %ls\n", path.c_str());
        return 2;
    }
    std::printf("[*] Target: %ls (%zu Byte)\n", path.c_str(), data.size());

    size_t tokenCnt = countOccurrences(data, LDSFLD_DLLOADER, sizeof(LDSFLD_DLLOADER));
    if (tokenCnt < 2) {
        std::fprintf(stderr, "[error] No match");
        return 3;
    }

    auto hits1 = findAll(data, SIG1, MASK1, sizeof(SIG1));
    auto hits2 = findAll(data, SIG2, MASK2, sizeof(SIG2));

    if (hits1.empty() && hits2.empty()) {
        std::fprintf(stderr, "[error] No match attribute");
        return 1;
    }
    if (hits1.size() != 1 || hits2.size() != 1) {
        std::fprintf(stderr, "[error] No match attribute 2\n");
        return 4;
    }

    if (!noBackup) {
        std::wstring bak = path + L".bak";
        DWORD attrs = GetFileAttributesW(bak.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            if (!writeFile(bak.c_str(), data)) {
                std::fwprintf(stderr, L"[Error] Failed to back up the file: %ls\n", bak.c_str());
                return 5;
            }
            std::printf("[*] The original file has been backed up -> %ls\n", bak.c_str());
        } else {
            std::printf("[*] The backup file already exists: %ls\n", bak.c_str());
        }
    }

    long p1 = hits1[0];
    std::printf("[+] Patch1 @ 0x%zX: LoaderInit -> Useing DlClientListLoader (48 Byte)\n", static_cast<size_t>(p1));
    std::memcpy(data.data() + p1, REPL1, sizeof(REPL1));

    long p2 = hits2[0];
    std::printf("[+] Patch2 @ 0x%zX: CardMinecraft.Visibility Collapsed -> Visible\n", static_cast<size_t>(p2) + SIG2_PATCH_OFF);
    data[p2 + SIG2_PATCH_OFF] = SIG2_PATCH_BYTE;

    if (!writeFile(path.c_str(), data)) {
        std::fwprintf(stderr, L"[Error] Failed to write to file: %ls\n", path.c_str());
        return 6;
    }
    std::printf("[*] Done: %ls\n", path.c_str());
    return 0;
}

int wmain(int argc, wchar_t** argv)
{
    bool noBackup = false;
    std::wstring path;

    if (argc >= 2) {
        path = argv[1];
        for (int i = 2; i < argc; ++i)
            if (wcscmp(argv[i], L"--no-backup") == 0) noBackup = true;
    } else {
        std::printf("[*] Select exe...\n\n");
        path = browseFile();
        if (path.empty()) {
            std::printf("[*] Cancelled select\n");
            std::printf("\nPress Enter to exit...");
            std::fflush(stdout);
            (void)std::getchar();
            return 2;
        }
    }

    int rc = patchFile(path, noBackup);

    if (argc < 2) {
        std::printf("\nPress Enter to exit...");
        std::fflush(stdout);
        (void)std::getchar();
    }
    return rc;
}
