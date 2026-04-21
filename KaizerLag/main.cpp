/*
    forked from alehacksp's hwid bypass.
    kaizer1308 pushed it into the x64 lane for newer exitlag builds.
*/

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <sstream>
#include <string>
#include <cstdint>
#include <iomanip>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

using std::cout;
using std::endl;
using std::hex;
using std::dec;
using std::string;
using std::vector;

#include "AuxFunctions.hpp"

static HANDLE g_console = GetStdHandle(STD_OUTPUT_HANDLE);

namespace Log {
    enum Color : WORD {
        RESET   = 0x07,
        RED     = 0x0C,
        GREEN   = 0x0A,
        YELLOW  = 0x0E,
        CYAN    = 0x0B,
        DIM     = 0x08,
        WHITE   = 0x0F,
        MAGENTA = 0x0D,
    };

    static void SetColor(Color c) { SetConsoleTextAttribute(g_console, c); }

    static void Print(Color tagColor, const char* tag, const char* msg) {
        SetColor(DIM);
        cout << "  [ ";
        SetColor(tagColor);
        cout << tag;
        SetColor(DIM);
        cout << " ]  ";
        SetColor(RESET);
        cout << msg << endl;
    }

    static void Error(const char* msg) {
        Print(RED, "FAIL", msg);
    }

    static void Ok(const char* msg) {
        Print(GREEN, " OK ", msg);
    }

    static void Info(const char* msg) {
        Print(CYAN, "INFO", msg);
    }

    static void Warn(const char* msg) {
        Print(YELLOW, "WARN", msg);
    }

    static void Debug(const char* msg) {
        SetColor(DIM);
        cout << "  [ ";
        SetColor(MAGENTA);
        cout << "DBG ";
        SetColor(DIM);
        cout << " ]  ";
        cout << msg << endl;
        SetColor(RESET);
    }

    static void Debug(const char* label, uintptr_t value) {
        SetColor(DIM);
        cout << "  [ ";
        SetColor(MAGENTA);
        cout << "DBG ";
        SetColor(DIM);
        cout << " ]  ";
        cout << label << ": ";
        SetColor(YELLOW);
        cout << "0x" << hex << value << dec << endl;
        SetColor(RESET);
    }

    static void Step(const char* msg) {
        cout << endl;
        SetColor(CYAN);
        cout << "  ==> ";
        SetColor(WHITE);
        cout << msg << endl;
        SetColor(RESET);
    }

    static void PrintCentered(const char* text) {
        int len = (int)strlen(text);
        int pad = (80 - len) / 2;
        if (pad > 0) cout << std::string(pad, ' ');
        cout << text << endl;
    }

    static void Spacer() { cout << endl; }

    static void Banner() {
        Spacer();
        SetColor(MAGENTA);
        PrintCentered(R"(   ____  __.      .__                    .____                  )");
        PrintCentered(R"(  |    |/ _|____  |__|_______ ___________|    |   _____     ____  )");
        SetColor(CYAN);
        PrintCentered(R"(  |      < \__  \ |  \___   // __ \_  __ \    |   \__  \   / ___\ )");
        PrintCentered(R"(  |    |  \ / __ \|  |/    /\  ___/|  | \/    |___ / __ \_/ /_/  >)");
        SetColor(GREEN);
        PrintCentered(R"(  |____|__ (____  /__/_____ \\___  >__|  |_______ (____  /\___  / )");
        PrintCentered(R"(          \/    \/         \/    \/              \/    \//_____/  )");
        Spacer();
        SetColor(DIM);
        PrintCentered("ExitLag Spoofer 2.1");
        SetColor(RESET);
        Spacer();
    }

    static void Summary(bool gaa_exitlag, bool gaa_qt, bool concurrency, uint32_t concurrency_val, bool hwid_protobuf) {
        Spacer();
        SetColor(CYAN);
        cout << "  ==> Spoofing Operations Overview" << endl;
        SetColor(RESET);
        Spacer();

        auto Row = [](bool ok, const char* name, const char* detail) {
            SetColor(DIM);
            cout << "      ";
            SetColor(ok ? GREEN : DIM);
            cout << (ok ? "*" : "-");
            SetColor(WHITE);
            cout << "  " << name;
            int pad = 24 - (int)strlen(name);
            for (int i = 0; i < pad; ++i) cout << ' ';
            SetColor(DIM);
            cout << "....  ";
            SetColor(ok ? GREEN : DIM);
            cout << detail << endl;
            SetColor(RESET);
        };

        Row(true,          "device_id",         "Randomized (SplitMix64)");
        Row(true,          "product_name",      "Randomized (SplitMix64)");
        Row(true,          "MACAddress",        "Randomized (SplitMix64)");
        Row(gaa_exitlag,   "macAddress (exe)",  "IAT Hook Injected");
        Row(gaa_qt,        "macAddress (Qt)",   "IAT Hook Injected");
        Row(hwid_protobuf, "auth (protobuf)",   "7 fields pre-spoofed (SplitMix64)");

        SetColor(DIM);
        cout << "      ";
        SetColor(concurrency ? GREEN : DIM);
        cout << (concurrency ? "*" : "-");
        SetColor(WHITE);
        cout << "  concurrency             ";
        SetColor(DIM);
        cout << "....  ";
        if (concurrency) {
            SetColor(GREEN);
            cout << "Returns " << dec << concurrency_val << endl;
        } else {
            SetColor(DIM);
            cout << "Unpatched" << endl;
        }

        SetColor(RESET);
        Spacer();
        Ok("Ready. You can now log in with a new ExitLag account.");
        Spacer();
    }
}


/*
    remote pe import walk.
    handy when the import name is stable but the code around it keeps sliding.
*/
static uintptr_t FindIATEntry(HANDLE hprocess, uintptr_t module_base,
                               const char* target_dll, const char* target_func)
{
    IMAGE_DOS_HEADER dos{};
    SIZE_T rd = 0;
    if (!ReadProcessMemory(hprocess, (LPCVOID)module_base, &dos, sizeof(dos), &rd) || rd != sizeof(dos)) {
        Log::Debug("FindIATEntry: failed to read DOS header");
        return 0;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        Log::Debug("FindIATEntry: invalid DOS signature");
        return 0;
    }

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadProcessMemory(hprocess, (LPCVOID)(module_base + dos.e_lfanew), &nt, sizeof(nt), &rd) || rd != sizeof(nt)) {
        Log::Debug("FindIATEntry: failed to read NT headers");
        return 0;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        Log::Debug("FindIATEntry: invalid NT signature");
        return 0;
    }

    auto& import_dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) {
        Log::Debug("FindIATEntry: no import directory");
        return 0;
    }

    uintptr_t import_rva = import_dir.VirtualAddress;
    uintptr_t cursor = module_base + import_rva;

    for (;;) {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        if (!ReadProcessMemory(hprocess, (LPCVOID)cursor, &desc, sizeof(desc), &rd))
            break;
        if (desc.Name == 0) break;

        char dll_name[256] = {};
        ReadProcessMemory(hprocess, (LPCVOID)(module_base + desc.Name), dll_name, sizeof(dll_name) - 1, &rd);

        if (_stricmp(dll_name, target_dll) == 0) {
            Log::Debug("FindIATEntry: found DLL in imports");

            uintptr_t orig_thunk_addr = module_base + desc.OriginalFirstThunk;
            uintptr_t iat_thunk_addr  = module_base + desc.FirstThunk;

            for (int idx = 0; ; ++idx) {
                IMAGE_THUNK_DATA64 thunk{};
                if (!ReadProcessMemory(hprocess, (LPCVOID)(orig_thunk_addr + idx * 8), &thunk, sizeof(thunk), &rd))
                    break;
                if (thunk.u1.AddressOfData == 0) break;

                if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    continue;

                char func_name[256] = {};
                ReadProcessMemory(hprocess, (LPCVOID)(module_base + (DWORD)thunk.u1.AddressOfData + 2),
                                  func_name, sizeof(func_name) - 1, &rd);

                if (strcmp(func_name, target_func) == 0) {
                    uintptr_t slot = iat_thunk_addr + idx * 8;
                    Log::Debug("FindIATEntry: found function IAT slot");
                    Log::Debug("  IAT slot address", slot);
                    return slot;
                }
            }
            Log::Debug("FindIATEntry: function not found in DLL's imports");
            return 0;
        }
        cursor += sizeof(desc);
    }

    Log::Debug("FindIATEntry: target DLL not found in import table");
    return 0;
}


/*
    wraps GetAdaptersAddresses and scrambles mac bytes in-place.
    the only offsets that matter here are +0x08 next, +0x50 mac, +0x58 len.
*/
static vector<uint8_t> BuildGAAHookShellcode(uintptr_t real_gaa_addr)
{
    vector<uint8_t> sc;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        sc.insert(sc.end(), bytes);
    };
    auto emit_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back((uint8_t)(v >> (i * 8)));
    };
    auto emit_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) sc.push_back((uint8_t)(v >> (i * 8)));
    };

    // win64 shim: save what we touch and forward the stack arg too.
    emit({ 0x53 });
    emit({ 0x56 });
    emit({ 0x48, 0x83, 0xEC, 0x28 });

    emit({ 0x49, 0x8B, 0xF1 });
    emit({ 0x48, 0x8B, 0x44, 0x24, 0x60 });
    emit({ 0x48, 0x89, 0x44, 0x24, 0x20 });

    emit({ 0x48, 0xB8 }); emit_u64(real_gaa_addr);
    emit({ 0xFF, 0xD0 });

    emit({ 0x89, 0xC3 });
    emit({ 0x85, 0xC0 });
    size_t jnz_done_pos = sc.size();
    emit({ 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 });

    // walk adapters and rewrite the first 6 mac bytes.
    emit({ 0x48, 0x8B, 0xCE });

    size_t walk_loop_pos = sc.size();

    emit({ 0x48, 0x85, 0xC9 });
    size_t jz_done_pos = sc.size();
    emit({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });

    emit({ 0x49, 0x89, 0xCB });

    emit({ 0x83, 0x79, 0x58, 0x06 });
    size_t jb_next_pos = sc.size();
    emit({ 0x72, 0x00 });

    emit({ 0x0F, 0x31 });
    emit({ 0x33, 0xC2 });
    emit({ 0x0D, 0x01, 0x00, 0x00, 0x00 });
    emit({ 0x44, 0x8B, 0xD0 });

    emit({ 0x4C, 0x8D, 0x41, 0x50 });
    emit({ 0x41, 0xB9, 0x06, 0x00, 0x00, 0x00 });

    size_t mac_loop_pos = sc.size();
    emit({ 0x45, 0x69, 0xD2, 0x6D, 0x4E, 0xC6, 0x41 });
    emit({ 0x41, 0x81, 0xC2, 0x39, 0x30, 0x00, 0x00 });
    emit({ 0x41, 0x8B, 0xC2 });
    emit({ 0xC1, 0xE8, 0x10 });
    emit({ 0x41, 0x88, 0x00 });
    emit({ 0x49, 0xFF, 0xC0 });
    emit({ 0x41, 0xFF, 0xC9 });
    int32_t mac_delta = (int32_t)mac_loop_pos - (int32_t)(sc.size() + 2);
    emit({ 0x75, (uint8_t)(int8_t)mac_delta });

    // keep the first byte looking like a sane local unicast mac.
    emit({ 0x80, 0x61, 0x50, 0xFE });
    emit({ 0x80, 0x49, 0x50, 0x02 });

    size_t next_adapter_pos = sc.size();
    int8_t jb_delta = (int8_t)((int32_t)next_adapter_pos - (int32_t)(jb_next_pos + 2));
    sc[jb_next_pos + 1] = (uint8_t)jb_delta;

    emit({ 0x49, 0x8B, 0x4B, 0x08 });
    int32_t walk_delta = (int32_t)walk_loop_pos - (int32_t)(sc.size() + 5);
    emit({ 0xE9 }); emit_u32((uint32_t)walk_delta);

    size_t done_pos = sc.size();

    // backpatch the forward exits now that we know where done landed.
    int32_t jnz_done_delta = (int32_t)done_pos - (int32_t)(jnz_done_pos + 6);
    sc[jnz_done_pos + 2] = (uint8_t)(jnz_done_delta);
    sc[jnz_done_pos + 3] = (uint8_t)(jnz_done_delta >> 8);
    sc[jnz_done_pos + 4] = (uint8_t)(jnz_done_delta >> 16);
    sc[jnz_done_pos + 5] = (uint8_t)(jnz_done_delta >> 24);

    int32_t jz_done_delta = (int32_t)done_pos - (int32_t)(jz_done_pos + 6);
    sc[jz_done_pos + 2] = (uint8_t)(jz_done_delta);
    sc[jz_done_pos + 3] = (uint8_t)(jz_done_delta >> 8);
    sc[jz_done_pos + 4] = (uint8_t)(jz_done_delta >> 16);
    sc[jz_done_pos + 5] = (uint8_t)(jz_done_delta >> 24);

    emit({ 0x89, 0xD8 });
    emit({ 0x48, 0x83, 0xC4, 0x28 });
    emit({ 0x5E });
    emit({ 0x5B });
    emit({ 0xC3 });

    return sc;
}


/*
    hooks api::start / api::login_again before auth protobuf gets built.
    StartupOptions +0x88 is the first hwid string, then the next slots sit 0x20 apart.
    the seed lives in trampoline memory so every entry point reuses the same fake hwid.
*/
static vector<uint8_t> BuildProtobufHwidHookShellcode(
    const uint8_t* stolen_bytes, size_t stolen_len,
    uintptr_t return_addr, uintptr_t seed_addr)
{
    vector<uint8_t> sc;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        sc.insert(sc.end(), bytes);
    };
    auto emit_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back((uint8_t)(v >> (i * 8)));
    };

    // save args first because rdtsc will trash edx.
    emit({ 0x51 });
    emit({ 0x52 });
    emit({ 0x41, 0x50 });

    // r11 walks the hwid-ish std::string slots.
    emit({ 0x4D, 0x8B, 0xD8 });
    emit({ 0x49, 0x81, 0xC3, 0x88, 0x00, 0x00, 0x00 });

    // lazy init the shared seed on first hit.
    emit({ 0x48, 0xB8 }); emit_u64(seed_addr);
    emit({ 0x4C, 0x8B, 0x10 });
    emit({ 0x4D, 0x85, 0xD2 });
    size_t jnz_seed = sc.size();
    emit({ 0x75, 0x00 });

    emit({ 0x50 });
    emit({ 0x0F, 0x31 });
    emit({ 0x48, 0xC1, 0xE2, 0x20 });
    emit({ 0x48, 0x09, 0xD0 });
    emit({ 0x48, 0x0D, 0x01, 0x00, 0x00, 0x00 });
    emit({ 0x49, 0x89, 0xC2 });
    emit({ 0x58 });
    emit({ 0x4C, 0x89, 0x10 });

    sc[jnz_seed + 1] = (uint8_t)(sc.size() - (jnz_seed + 2));

    // rewrite the 7 adjacent std::string fields as lowercase hex.
    for (int field = 0; field < 7; ++field) {
        if (field > 0) {
            emit({ 0x49, 0x83, 0xC3, 0x20 });
        }

        emit({ 0x4D, 0x8B, 0x43, 0x10 });
        emit({ 0x4D, 0x85, 0xC0 });
        size_t jz_skip = sc.size();
        emit({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });

        // cap weird lengths so a bad struct doesn't run off into space.
        emit({ 0x49, 0x83, 0xF8, 0x3F });
        emit({ 0x76, 0x07 });
        emit({ 0x49, 0xC7, 0xC0, 0x3F, 0x00, 0x00, 0x00 });

        // msvc std::string: inline below 16, heap pointer otherwise.
        emit({ 0x49, 0x83, 0x7B, 0x18, 0x10 });
        emit({ 0x73, 0x05 });
        emit({ 0x49, 0x8B, 0xC3 });
        emit({ 0xEB, 0x03 });
        emit({ 0x49, 0x8B, 0x03 });

        size_t loop_start = sc.size();

        emit({ 0x48, 0xBA }); emit_u64(0x9E3779B97F4A7C15ULL);
        emit({ 0x49, 0x01, 0xD2 });
        emit({ 0x4C, 0x89, 0xD1 });
        emit({ 0x48, 0x89, 0xCA });
        emit({ 0x48, 0xC1, 0xEA, 0x1E });
        emit({ 0x48, 0x31, 0xD1 });
        emit({ 0x48, 0xBA }); emit_u64(0xBF58476D1CE4E5B9ULL);
        emit({ 0x48, 0x0F, 0xAF, 0xCA });
        emit({ 0x48, 0x89, 0xCA });
        emit({ 0x48, 0xC1, 0xEA, 0x1B });
        emit({ 0x48, 0x31, 0xD1 });
        emit({ 0x48, 0xBA }); emit_u64(0x94D049BB133111EBULL);
        emit({ 0x48, 0x0F, 0xAF, 0xCA });
        emit({ 0x48, 0x89, 0xCA });
        emit({ 0x48, 0xC1, 0xEA, 0x1F });
        emit({ 0x48, 0x31, 0xD1 });

        emit({ 0x41, 0x89, 0xC9 });
        emit({ 0x41, 0x83, 0xE1, 0x0F });
        emit({ 0x41, 0x83, 0xF9, 0x0A });
        emit({ 0x72, 0x06 });
        emit({ 0x41, 0x83, 0xC1, 0x57 });
        emit({ 0xEB, 0x04 });
        emit({ 0x41, 0x83, 0xC1, 0x30 });
        emit({ 0x44, 0x88, 0x08 });
        emit({ 0x48, 0xFF, 0xC0 });
        emit({ 0x49, 0xFF, 0xC8 });

        int16_t loop_delta_tmp = (int32_t)loop_start - (int32_t)(sc.size() + 2);
        if (loop_delta_tmp < -128) {
            // this body gets too chunky for rel8 on some builds.
            int32_t big_loop = (int32_t)loop_start - (int32_t)(sc.size() + 6);
            emit({ 0x0F, 0x85 });
            sc.push_back((uint8_t)(big_loop & 0xFF));
            sc.push_back((uint8_t)((big_loop >> 8) & 0xFF));
            sc.push_back((uint8_t)((big_loop >> 16) & 0xFF));
            sc.push_back((uint8_t)((big_loop >> 24) & 0xFF));
        } else {
            int8_t loop_delta = (int8_t)loop_delta_tmp;
            emit({ 0x75, (uint8_t)loop_delta });
        }

        // skip target only exists after the field body is emitted.
        int32_t skip_dist = (int32_t)sc.size() - (int32_t)(jz_skip + 6);
        sc[jz_skip + 2] = (uint8_t)(skip_dist & 0xFF);
        sc[jz_skip + 3] = (uint8_t)((skip_dist >> 8) & 0xFF);
        sc[jz_skip + 4] = (uint8_t)((skip_dist >> 16) & 0xFF);
        sc[jz_skip + 5] = (uint8_t)((skip_dist >> 24) & 0xFF);
    }

    // replay the bytes we stole, then land back in the real function.
    emit({ 0x41, 0x58 });
    emit({ 0x5A });
    emit({ 0x59 });

    for (size_t i = 0; i < stolen_len; ++i)
        sc.push_back(stolen_bytes[i]);

    emit({ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 });
    emit_u64(return_addr);

    return sc;
}

// same seed, but this one rewrites API::get_user_hwid's return string directly.
static vector<uint8_t> BuildGetHwidHookShellcode(uintptr_t seed_addr)
{
    vector<uint8_t> sc;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        sc.insert(sc.end(), bytes);
    };
    auto emit_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back((uint8_t)(v >> (i * 8)));
    };

    emit({ 0x48, 0x8D, 0x41, 0x50 });

    emit({ 0x50 });
    emit({ 0x51 });
    emit({ 0x52 });
    emit({ 0x41, 0x50 });
    emit({ 0x41, 0x51 });
    emit({ 0x41, 0x52 });
    emit({ 0x41, 0x53 });

    emit({ 0x49, 0x89, 0xC3 });

    // get_user_hwid can race ahead of start(), so init the seed here too.
    emit({ 0x48, 0xB8 }); emit_u64(seed_addr);
    emit({ 0x4C, 0x8B, 0x10 });
    emit({ 0x4D, 0x85, 0xD2 });
    size_t jnz_seed = sc.size();
    emit({ 0x75, 0x00 });

    emit({ 0x50 });
    emit({ 0x0F, 0x31 });
    emit({ 0x48, 0xC1, 0xE2, 0x20 });
    emit({ 0x48, 0x09, 0xD0 });
    emit({ 0x48, 0x0D, 0x01, 0x00, 0x00, 0x00 });
    emit({ 0x49, 0x89, 0xC2 });
    emit({ 0x58 });
    emit({ 0x4C, 0x89, 0x10 });

    sc[jnz_seed + 1] = (uint8_t)(sc.size() - (jnz_seed + 2));
    emit({ 0x4D, 0x8B, 0x43, 0x10 });
    emit({ 0x4D, 0x85, 0xC0 });
    size_t jz_skip = sc.size();
    emit({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 });

    // same safety cap as the protobuf hook.
    emit({ 0x49, 0x83, 0xF8, 0x3F });
    emit({ 0x76, 0x07 });
    emit({ 0x49, 0xC7, 0xC0, 0x3F, 0x00, 0x00, 0x00 });

    // same msvc std::string split: inline vs heap.
    emit({ 0x49, 0x83, 0x7B, 0x18, 0x10 });
    emit({ 0x73, 0x05 });
    emit({ 0x49, 0x8B, 0xC3 });
    emit({ 0xEB, 0x03 });
    emit({ 0x49, 0x8B, 0x03 });

    size_t loop_start = sc.size();

    emit({ 0x48, 0xBA }); emit_u64(0x9E3779B97F4A7C15ULL);
    emit({ 0x49, 0x01, 0xD2 });
    emit({ 0x4C, 0x89, 0xD1 });
    emit({ 0x48, 0x89, 0xCA });
    emit({ 0x48, 0xC1, 0xEA, 0x1E });
    emit({ 0x48, 0x31, 0xD1 });
    emit({ 0x48, 0xBA }); emit_u64(0xBF58476D1CE4E5B9ULL);
    emit({ 0x48, 0x0F, 0xAF, 0xCA });
    emit({ 0x48, 0x89, 0xCA });
    emit({ 0x48, 0xC1, 0xEA, 0x1B });
    emit({ 0x48, 0x31, 0xD1 });
    emit({ 0x48, 0xBA }); emit_u64(0x94D049BB133111EBULL);
    emit({ 0x48, 0x0F, 0xAF, 0xCA });
    emit({ 0x48, 0x89, 0xCA });
    emit({ 0x48, 0xC1, 0xEA, 0x1F });
    emit({ 0x48, 0x31, 0xD1 });

    emit({ 0x41, 0x89, 0xC9 });
    emit({ 0x41, 0x83, 0xE1, 0x0F });
    emit({ 0x41, 0x83, 0xF9, 0x0A });
    emit({ 0x72, 0x06 });
    emit({ 0x41, 0x83, 0xC1, 0x57 });
    emit({ 0xEB, 0x04 });
    emit({ 0x41, 0x83, 0xC1, 0x30 });
    emit({ 0x44, 0x88, 0x08 });
    emit({ 0x48, 0xFF, 0xC0 });
    emit({ 0x49, 0xFF, 0xC8 });

    int16_t loop_delta_tmp = (int32_t)loop_start - (int32_t)(sc.size() + 2);
    if (loop_delta_tmp < -128) {
        // same rel32 escape hatch as above.
        int32_t big_loop = (int32_t)loop_start - (int32_t)(sc.size() + 6);
        emit({ 0x0F, 0x85 });
        sc.push_back((uint8_t)(big_loop & 0xFF));
        sc.push_back((uint8_t)((big_loop >> 8) & 0xFF));
        sc.push_back((uint8_t)((big_loop >> 16) & 0xFF));
        sc.push_back((uint8_t)((big_loop >> 24) & 0xFF));
    } else {
        int8_t loop_delta = (int8_t)loop_delta_tmp;
        emit({ 0x75, (uint8_t)loop_delta });
    }

    int32_t skip_dist = (int32_t)sc.size() - (int32_t)(jz_skip + 6);
    sc[jz_skip + 2] = (uint8_t)(skip_dist & 0xFF);
    sc[jz_skip + 3] = (uint8_t)((skip_dist >> 8) & 0xFF);
    sc[jz_skip + 4] = (uint8_t)((skip_dist >> 16) & 0xFF);
    sc[jz_skip + 5] = (uint8_t)((skip_dist >> 24) & 0xFF);

    emit({ 0x41, 0x5B });
    emit({ 0x41, 0x5A });
    emit({ 0x41, 0x59 });
    emit({ 0x41, 0x58 });
    emit({ 0x5A });
    emit({ 0x59 });
    emit({ 0x58 });

    emit({ 0xC3 });

    return sc;
}


/*
    inline hook for the device_id / product_name / MACAddress serializer path.
    seed mixes rdtsc, peb, rsp, and a shared counter so hot loops do not clone values.
    stolen bytes get replayed, so rbp offset drift between builds is fine.
*/
static vector<uint8_t> BuildShellcode(const uint8_t* stolen_bytes, size_t stolen_len,
                                      uintptr_t iat_slot, uintptr_t return_addr,
                                      uintptr_t counter_slot_addr)
{
    vector<uint8_t> sc;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        sc.insert(sc.end(), bytes);
    };
    auto emit_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) sc.push_back((uint8_t)(v >> (i * 8)));
    };
    auto emit_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back((uint8_t)(v >> (i * 8)));
    };
    auto patch_u8 = [&](size_t pos, uint8_t v) { sc[pos] = v; };
    auto patch_u32 = [&](size_t pos, uint32_t v) {
        for (int i = 0; i < 4; ++i) sc[pos + i] = (uint8_t)(v >> (i * 8));
    };

    // save every register this blob dirties.
    emit({ 0x50 });
    emit({ 0x53 });
    emit({ 0x51 });
    emit({ 0x52 });
    emit({ 0x55 });
    emit({ 0x41, 0x52 });
    emit({ 0x41, 0x53 });
    emit({ 0x41, 0x54 });
    emit({ 0x41, 0x55 });
    emit({ 0x41, 0x56 });

    // mash together a seed with a few moving bits from the current run.
    emit({ 0x0F, 0x31 });
    emit({ 0x48, 0xC1, 0xE2, 0x20 });
    emit({ 0x48, 0x09, 0xD0 });
    emit({ 0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00 });
    emit({ 0x48, 0x31, 0xC8 });
    emit({ 0x48, 0x31, 0xE0 });
    emit({ 0xB9, 0x01, 0x00, 0x00, 0x00 });
    emit({ 0x48, 0xBA }); emit_u64((uint64_t)counter_slot_addr);
    emit({ 0xF0, 0x48, 0x0F, 0xC1, 0x0A });
    emit({ 0x48, 0x31, 0xC8 });
    emit({ 0x48, 0xBA }); emit_u64(0x9E3779B97F4A7C15ULL);
    emit({ 0x48, 0x01, 0xD0 });
    emit({ 0x49, 0x89, 0xC2 });

    // r11 walks the 3 adjacent std::wstring fields hanging off rbx.
    emit({ 0x49, 0x89, 0xDB });
    emit({ 0x41, 0xBC, 0x03, 0x00, 0x00, 0x00 });

    size_t outer_loop_pos = sc.size();

    emit({ 0x49, 0x8B, 0x4B, 0x18 });

    emit({ 0x48, 0x83, 0xF9, 0x3F });
    emit({ 0x76, 0x05 });
    emit({ 0xB9, 0x3F, 0x00, 0x00, 0x00 });

    emit({ 0x48, 0x83, 0xF9, 0x08 });
    emit({ 0x72, 0x05 });
    emit({ 0x4D, 0x8B, 0x33 });
    emit({ 0xEB, 0x03 });
    emit({ 0x4D, 0x89, 0xDE });

    emit({ 0x49, 0x89, 0xCD });
    emit({ 0x4D, 0x85, 0xED });

    size_t jz_skip_pos = sc.size();
    emit({ 0x74, 0x00 });

    // refill a 16-nibble pool from splitmix64 whenever ebp hits 0.
    emit({ 0x31, 0xED });

    size_t hex_loop_pos = sc.size();

    emit({ 0x85, 0xED });
    size_t jnz_have_pos = sc.size();
    emit({ 0x75, 0x00 });

    emit({ 0x48, 0xBA }); emit_u64(0x9E3779B97F4A7C15ULL);
    emit({ 0x49, 0x01, 0xD2 });
    emit({ 0x4C, 0x89, 0xD0 });
    emit({ 0x48, 0x89, 0xC2 });
    emit({ 0x48, 0xC1, 0xEA, 0x1E });
    emit({ 0x48, 0x31, 0xD0 });
    emit({ 0x48, 0xBA }); emit_u64(0xBF58476D1CE4E5B9ULL);
    emit({ 0x48, 0x0F, 0xAF, 0xC2 });
    emit({ 0x48, 0x89, 0xC2 });
    emit({ 0x48, 0xC1, 0xEA, 0x1B });
    emit({ 0x48, 0x31, 0xD0 });
    emit({ 0x48, 0xBA }); emit_u64(0x94D049BB133111EBULL);
    emit({ 0x48, 0x0F, 0xAF, 0xC2 });
    emit({ 0x48, 0x89, 0xC2 });
    emit({ 0x48, 0xC1, 0xEA, 0x1F });
    emit({ 0x48, 0x31, 0xD0 });
    emit({ 0x48, 0x89, 0xC3 });
    emit({ 0xBD, 0x10, 0x00, 0x00, 0x00 });

    size_t have_nibble_pos = sc.size();
    patch_u8(jnz_have_pos + 1,
             (uint8_t)(int8_t)((int64_t)have_nibble_pos - (int64_t)(jnz_have_pos + 2)));

    // turn the low nibble into lowercase hex.
    emit({ 0x89, 0xD8 });
    emit({ 0x83, 0xE0, 0x0F });
    emit({ 0x3C, 0x0A });
    size_t jb_digit_pos = sc.size();
    emit({ 0x72, 0x00 });
    emit({ 0x04, 0x57 });
    size_t jmp_write_pos = sc.size();
    emit({ 0xEB, 0x00 });
    size_t digit_pos = sc.size();
    emit({ 0x04, 0x30 });
    size_t write_char_pos = sc.size();
    patch_u8(jb_digit_pos + 1,
             (uint8_t)(int8_t)((int64_t)digit_pos - (int64_t)(jb_digit_pos + 2)));
    patch_u8(jmp_write_pos + 1,
             (uint8_t)(int8_t)((int64_t)write_char_pos - (int64_t)(jmp_write_pos + 2)));

    emit({ 0x66, 0x41, 0x89, 0x06 });
    emit({ 0x49, 0x83, 0xC6, 0x02 });
    emit({ 0x48, 0xC1, 0xEB, 0x04 });
    emit({ 0xFF, 0xCD });
    emit({ 0x49, 0xFF, 0xCD });

    emit({ 0x4D, 0x85, 0xED });
    {
        size_t jnz_back_pos = sc.size();
        emit({ 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 });
        int32_t d = (int32_t)((int64_t)hex_loop_pos - (int64_t)(jnz_back_pos + 6));
        patch_u32(jnz_back_pos + 2, (uint32_t)d);
    }

    // write the widened string and keep _Mysize in sync.
    emit({ 0x66, 0x41, 0xC7, 0x06, 0x00, 0x00 });
    emit({ 0x49, 0x89, 0x4B, 0x10 });

    size_t jmp_after_pos = sc.size();
    emit({ 0xEB, 0x00 });

    size_t skip_field_pos = sc.size();
    patch_u8(jz_skip_pos + 1,
             (uint8_t)(int8_t)((int64_t)skip_field_pos - (int64_t)(jz_skip_pos + 2)));
    emit({ 0x66, 0x41, 0xC7, 0x06, 0x00, 0x00 });
    emit({ 0x49, 0xC7, 0x43, 0x10, 0x00, 0x00, 0x00, 0x00 });

    size_t after_field_pos = sc.size();
    patch_u8(jmp_after_pos + 1,
             (uint8_t)(int8_t)((int64_t)after_field_pos - (int64_t)(jmp_after_pos + 2)));

    emit({ 0x49, 0x83, 0xC3, 0x20 });
    emit({ 0x41, 0xFF, 0xCC });
    {
        size_t jnz_outer_pos = sc.size();
        emit({ 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 });
        int32_t d = (int32_t)((int64_t)outer_loop_pos - (int64_t)(jnz_outer_pos + 6));
        patch_u32(jnz_outer_pos + 2, (uint32_t)d);
    }

    emit({ 0x41, 0x5E });
    emit({ 0x41, 0x5D });
    emit({ 0x41, 0x5C });
    emit({ 0x41, 0x5B });
    emit({ 0x41, 0x5A });
    emit({ 0x5D });
    emit({ 0x5A });
    emit({ 0x59 });
    emit({ 0x5B });
    emit({ 0x58 });

    // replay the stolen bytes, call the real import, then jump back.
    for (size_t i = 0; i < stolen_len; ++i)
        sc.push_back(stolen_bytes[i]);

    emit({ 0x48, 0xB8 }); emit_u64(iat_slot);
    emit({ 0xFF, 0x10 });

    emit({ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 });
    emit_u64(return_addr);

    (void)emit_u32;
    return sc;
}


// quick iat swap helper for GetAdaptersAddresses.
static bool InstallIATHook(HANDLE hprocess, uintptr_t module_base,
                            const char* dll_name, const char* func_name,
                            LPVOID trampoline_region, size_t& offset,
                            const char* label)
{
    Log::Debug(label);

    uintptr_t iat_slot = FindIATEntry(hprocess, module_base, dll_name, func_name);
    if (!iat_slot) {
        Log::Error("IAT entry not found.");
        return false;
    }
    Log::Debug("IAT slot", iat_slot);

    uintptr_t real_func = 0;
    SIZE_T rd = 0;
    if (!ReadProcessMemory(hprocess, (LPCVOID)iat_slot, &real_func, sizeof(real_func), &rd) || rd != 8) {
        Log::Error("Failed to read real function pointer from IAT.");
        return false;
    }
    Log::Debug("Real function address", real_func);

    vector<uint8_t> sc = BuildGAAHookShellcode(real_func);
    Log::Debug("Wrapper shellcode size", sc.size());

    uintptr_t wrapper_addr = (uintptr_t)trampoline_region + offset;
    SIZE_T written = 0;
    if (!WriteProcessMemory(hprocess, (LPVOID)wrapper_addr, sc.data(), sc.size(), &written) || written != sc.size()) {
        Log::Error("Failed to write wrapper shellcode.");
        return false;
    }
    offset += sc.size();
    // keep each shellcode blob 16-byte aligned.
    offset = (offset + 15) & ~(size_t)15;

    Log::Debug("Wrapper written at", wrapper_addr);

    DWORD old_prot = 0;
    VirtualProtectEx(hprocess, (LPVOID)iat_slot, 8, PAGE_READWRITE, &old_prot);

    if (!WriteProcessMemory(hprocess, (LPVOID)iat_slot, &wrapper_addr, sizeof(wrapper_addr), &written) || written != 8) {
        Log::Error("Failed to patch IAT slot.");
        VirtualProtectEx(hprocess, (LPVOID)iat_slot, 8, old_prot, &old_prot);
        return false;
    }

    VirtualProtectEx(hprocess, (LPVOID)iat_slot, 8, old_prot, &old_prot);

    Log::Ok("IAT hook installed.");
    return true;
}


static int run_bypass()
{
    bool gaa_hooked_exitlag = false;
    bool gaa_hooked_qt      = false;
    bool concurrency_ok     = false;
    uint32_t spoofed_concurrency = 0;
    bool     hwid_hooked_protobuf = false;


    Log::Step("Locating ExitLag.exe process");

    DWORD pid = GetPIdByProcessName("ExitLag.exe");
    while (!pid) {
        Log::Info("Waiting for ExitLag.exe...");
        Sleep(500);
        pid = GetPIdByProcessName("ExitLag.exe");
    }
    Log::Debug("PID", (uintptr_t)pid);

    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hprocess || hprocess == INVALID_HANDLE_VALUE) {
        Log::Error("OpenProcess failed — run as Administrator.");
        Sleep(5000);
        return 1;
    }
    Log::Ok("Process handle acquired.");

    // let exitlag finish mapping before the pattern scan.
    Sleep(1000);

    Log::Step("Resolving module base");

    uintptr_t module_base = GetModuleAddressByName(pid, "ExitLag.exe");
    if (!module_base) {
        Log::Error("GetModuleAddress failed — ensure bypass is built as x64.");
        CloseHandle(hprocess);
        Sleep(5000);
        return 1;
    }
    Log::Debug("ExitLag.exe base", module_base);

    SIZE_T image_size = GetModuleImageSize(hprocess, module_base);
    if (!image_size) {
        image_size = 0x08000000;
        Log::Debug("Using fallback image size (128 MiB)");
    }
    Log::Debug("Image size", image_size);

    Log::Step("Allocating trampoline memory");

    LPVOID trampoline = VirtualAllocEx(hprocess, nullptr, 0x4000,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        Log::Error("VirtualAllocEx failed.");
        CloseHandle(hprocess);
        Sleep(5000);
        return 1;
    }
    Log::Ok("Trampoline allocated.");
    Log::Debug("Trampoline region", (uintptr_t)trampoline);

    // trampoline layout: +0 counter slot, +8 shared protobuf seed.
    const uintptr_t counter_slot_addr = (uintptr_t)trampoline;
    const uintptr_t proto_seed_addr = (uintptr_t)trampoline + 8;
    size_t tramp_offset = 16;

    Log::Step("Installing device_id / product_name inline hook");

    // start tight, then loosen the ida pattern until the same call site shows up.
    const char* patterns[] = {
        // p0: exact 5.20.x-ish anchor.
        "48 8B D3 48 8D 4D 27 FF 15 ?? ?? ?? ?? 90 "
        "48 8B D0 48 8D 4D CF FF 15 ?? ?? ?? ?? 90",

        // p1: same shape, wildcarded rbp offset.
        "48 8B D3 48 8D 4D ?? FF 15 ?? ?? ?? ?? 90",

        // p2: tiny fallback near the same import call.
        "48 8B D3 48 8D ?? ?? FF 15 ?? ?? ?? ?? 90",

        nullptr
    };

    uintptr_t hook_addr = 0;
    int pattern_idx = -1;
    for (int pi = 0; patterns[pi]; ++pi) {
        vector<byte> pattern_bytes;
        string mask;
        PatternStringToBytePatternAndMask(patterns[pi], &pattern_bytes, &mask);

        hook_addr = ExPatternScanByStartAddress(
            hprocess, module_base, image_size, pattern_bytes, mask);

        if (hook_addr) {
            pattern_idx = pi;
            {
                char buf[64];
                snprintf(buf, sizeof(buf), "Pattern P%d matched.", pi);
                Log::Ok(buf);
            }
            break;
        }
        {
            char buf[64];
            snprintf(buf, sizeof(buf), "Pattern P%d — no match, trying next...", pi);
            Log::Debug(buf);
        }
    }

    if (!hook_addr) {
        Log::Error("No pattern matched — ExitLag binary has changed.");
        Log::Info("Open the new binary in IDA, find the fromStdWString call");
        Log::Info("near the \"device_id\" string ref, and add a new pattern.");
        VirtualFreeEx(hprocess, trampoline, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        Sleep(10000);
        return 1;
    }

    Log::Debug("Hook site", hook_addr);

    // replay these bytes in the trampoline so rbp offset drift does not matter.
    const size_t STOLEN_LEN = 7;
    uint8_t stolen[STOLEN_LEN] = {};
    SIZE_T rd = 0;
    if (!ReadProcessMemory(hprocess, (LPCVOID)hook_addr, stolen, STOLEN_LEN, &rd) || rd != STOLEN_LEN) {
        Log::Error("Failed to read stolen instructions from hook site.");
        VirtualFreeEx(hprocess, trampoline, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        Sleep(5000);
        return 1;
    }
    Log::Debug("Stolen bytes read OK (7 bytes)");

    // ff 15 disp32 starts right after the stolen bytes.
    int32_t disp32 = 0;
    if (!ReadProcessMemory(hprocess, (LPCVOID)(hook_addr + 9), &disp32, sizeof(disp32), &rd) || rd != sizeof(disp32)) {
        Log::Error("Failed to read fromStdWString displacement.");
        VirtualFreeEx(hprocess, trampoline, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        Sleep(5000);
        return 1;
    }
    uintptr_t iat_slot = hook_addr + 13 + (int64_t)disp32;
    Log::Debug("fromStdWString IAT slot", iat_slot);

    const uintptr_t return_addr = hook_addr + 14;
    vector<uint8_t> sc = BuildShellcode(stolen, STOLEN_LEN, iat_slot, return_addr, counter_slot_addr);
    Log::Debug("Inline hook shellcode size", sc.size());

    if (sc.empty()) {
        Log::Error("BuildShellcode returned empty.");
        VirtualFreeEx(hprocess, trampoline, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        Sleep(5000);
        return 1;
    }

    uintptr_t inline_hook_addr = (uintptr_t)trampoline + tramp_offset;
    SIZE_T written = 0;
    if (!WriteProcessMemory(hprocess, (LPVOID)inline_hook_addr, sc.data(), sc.size(), &written) || written != sc.size()) {
        Log::Error("WriteProcessMemory (inline hook shellcode) failed.");
        VirtualFreeEx(hprocess, trampoline, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        Sleep(5000);
        return 1;
    }
    tramp_offset += sc.size();
    tramp_offset = (tramp_offset + 15) & ~(size_t)15;

    Log::Debug("Inline hook shellcode @", inline_hook_addr);

    uint8_t hook_patch[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0, 0, 0, 0, 0, 0, 0, 0
    };
    for (int i = 0; i < 8; ++i) hook_patch[6 + i] = (uint8_t)(inline_hook_addr >> (i * 8));

    DWORD old_prot = 0;
    if (!VirtualProtectEx(hprocess, (LPVOID)hook_addr, sizeof(hook_patch), PAGE_EXECUTE_READWRITE, &old_prot)) {
        Log::Error("VirtualProtectEx (hook site) failed.");
        VirtualFreeEx(hprocess, trampoline, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        Sleep(5000);
        return 1;
    }

    if (!WriteProcessMemory(hprocess, (LPVOID)hook_addr, hook_patch, sizeof(hook_patch), &written) || written != sizeof(hook_patch)) {
        Log::Error("WriteProcessMemory (hook patch) failed.");
        VirtualProtectEx(hprocess, (LPVOID)hook_addr, sizeof(hook_patch), old_prot, &old_prot);
        VirtualFreeEx(hprocess, trampoline, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        Sleep(5000);
        return 1;
    }

    VirtualProtectEx(hprocess, (LPVOID)hook_addr, sizeof(hook_patch), old_prot, &old_prot);
    FlushInstructionCache(hprocess, (LPCVOID)hook_addr, sizeof(hook_patch));

    Log::Ok("Inline hook installed (device_id / product_name / MACAddress).");

    Log::Step("Installing GetAdaptersAddresses IAT hook (ExitLag.exe)");

    gaa_hooked_exitlag = InstallIATHook(
        hprocess, module_base,
        "IPHLPAPI.DLL", "GetAdaptersAddresses",
        trampoline, tramp_offset,
        "Hooking ExitLag.exe -> IPHLPAPI.DLL"
    );

    if (!gaa_hooked_exitlag) {
        // some builds import it in lowercase.
        gaa_hooked_exitlag = InstallIATHook(
            hprocess, module_base,
            "iphlpapi.dll", "GetAdaptersAddresses",
            trampoline, tramp_offset,
            "Retrying with lowercase DLL name"
        );
    }

    if (gaa_hooked_exitlag) {
        Log::Ok("GetAdaptersAddresses IAT hook active in ExitLag.exe.");
    } else {
        Log::Warn("Could not hook GetAdaptersAddresses in ExitLag.exe.");
        Log::Info("MAC address in the detailed adapter JSON may leak.");
    }

    Log::Step("Looking for Qt6Network.dll IAT hook");

    uintptr_t qt_net_base = GetModuleAddressByName(pid, "Qt6Network.dll");
    if (qt_net_base) {
        Log::Debug("Qt6Network.dll base", qt_net_base);

        // qt sometimes keeps its own import path for adapters.
        bool gaa_qt = InstallIATHook(
            hprocess, qt_net_base,
            "IPHLPAPI.DLL", "GetAdaptersAddresses",
            trampoline, tramp_offset,
            "Hooking Qt6Network.dll -> IPHLPAPI.DLL"
        );

        if (!gaa_qt) {
            gaa_qt = InstallIATHook(
                hprocess, qt_net_base,
                "iphlpapi.dll", "GetAdaptersAddresses",
                trampoline, tramp_offset,
                "Retrying lowercase DLL name"
            );
        }

        if (gaa_qt) {
            Log::Ok("GetAdaptersAddresses IAT hook active in Qt6Network.dll.");
            gaa_hooked_qt = true;
        } else {
            Log::Info("Qt6Network.dll doesn't import GetAdaptersAddresses directly.");
        }
    } else {
        Log::Info("Qt6Network.dll not loaded — MAC spoofing relies on ExitLag.exe IAT hook.");
    }

    Log::Step("Patching _Thrd_hardware_concurrency (IAT lookup)");

    uintptr_t thrd_iat_slot = FindIATEntry(hprocess, module_base,
                                            "MSVCP140.dll", "_Thrd_hardware_concurrency");
    if (!thrd_iat_slot) {
        thrd_iat_slot = FindIATEntry(hprocess, module_base,
                                     "msvcp140.dll", "_Thrd_hardware_concurrency");
    }

    if (thrd_iat_slot) {
        uintptr_t thrd_hw_addr = 0;
        if (ReadProcessMemory(hprocess, (LPCVOID)thrd_iat_slot, &thrd_hw_addr, sizeof(thrd_hw_addr), &rd) && rd == 8 && thrd_hw_addr) {
            Log::Debug("_Thrd_hardware_concurrency resolved at", thrd_hw_addr);

            // keep the spoof believable.
            const uint32_t plausible_counts[] = { 4, 6, 8, 12, 16 };
            srand(GetTickCount());
            spoofed_concurrency = plausible_counts[rand() % 5];

            uint8_t concurrency_patch[6] = {
                0xB8, 0x00, 0x00, 0x00, 0x00,
                0xC3
            };
            concurrency_patch[1] = (uint8_t)(spoofed_concurrency);
            concurrency_patch[2] = (uint8_t)(spoofed_concurrency >> 8);
            concurrency_patch[3] = (uint8_t)(spoofed_concurrency >> 16);
            concurrency_patch[4] = (uint8_t)(spoofed_concurrency >> 24);

            DWORD prot2 = 0;
            if (VirtualProtectEx(hprocess, (LPVOID)thrd_hw_addr, 6, PAGE_EXECUTE_READWRITE, &prot2)) {
                if (WriteProcessMemory(hprocess, (LPVOID)thrd_hw_addr, concurrency_patch, 6, &written) && written == 6) {
                    VirtualProtectEx(hprocess, (LPVOID)thrd_hw_addr, 6, prot2, &prot2);
                    FlushInstructionCache(hprocess, (LPCVOID)thrd_hw_addr, 6);

                    concurrency_ok = true;
                    {
                        char buf[80];
                        snprintf(buf, sizeof(buf), "Concurrency spoofed to %u threads.", spoofed_concurrency);
                        Log::Ok(buf);
                    }
                } else {
                    VirtualProtectEx(hprocess, (LPVOID)thrd_hw_addr, 6, prot2, &prot2);
                    Log::Error("Failed to write concurrency patch.");
                }
            } else {
                Log::Error("VirtualProtectEx failed for concurrency patch.");
            }
        } else {
            Log::Error("Failed to read resolved address from IAT slot.");
        }
    } else {
        Log::Warn("_Thrd_hardware_concurrency not found in IAT - skipped.");
        Log::Info("Non-fatal: other spoofing vectors remain active.");
    }

    Log::Step("Installing libexitlag.dll HWID protobuf hook");

    // libexitlag gets delay-loaded a lot, so poll for a bit.
    uintptr_t libexitlag_base = 0;
    for (int wait_i = 0; wait_i < 30; ++wait_i) {
        libexitlag_base = GetModuleAddressByName(pid, "libexitlag.dll");
        if (libexitlag_base) break;
        if (wait_i == 0) Log::Info("Waiting for libexitlag.dll to load...");
        Sleep(500);
    }

    if (libexitlag_base) {
        Log::Debug("libexitlag.dll base", libexitlag_base);

        SIZE_T libex_size = GetModuleImageSize(hprocess, libexitlag_base);
        if (!libex_size) {
            libex_size = 0x04000000;
            Log::Debug("Using fallback libexitlag image size");
        }

        // start/login_again share the same entry shape; getter is the odd one out.
        struct ProtoTarget {
            const char* name;
            uintptr_t   rva;
            bool        is_getter;
        };
        const ProtoTarget proto_targets[] = {
            { "API::start",       0x65B90, false },
            { "API::login_again", 0x66200, false },
            { "API::get_user_hwid", 0x0E370, true },
        };

        // quick sanity check so stale rvAs do not patch garbage.
        static const uint8_t expected_prologue[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08,
            0x48, 0x89, 0x6C, 0x24, 0x18,
            0x48, 0x89, 0x74, 0x24, 0x20,
        };

        int proto_hooks_installed = 0;

        for (int ti = 0; ti < 3; ++ti) {
            const auto& target = proto_targets[ti];
            uintptr_t hook_addr = libexitlag_base + target.rva;
            Log::Debug(target.name, hook_addr);

            const size_t PROTO_STOLEN = target.is_getter ? 14 : 20;
            uint8_t proto_stolen[32] = {};

            if (!ReadProcessMemory(hprocess, (LPCVOID)hook_addr,
                                   proto_stolen, PROTO_STOLEN, &rd)
                || rd != PROTO_STOLEN)
            {
                char buf[128];
                snprintf(buf, sizeof(buf),
                         "Failed to read prologue of %s.", target.name);
                Log::Error(buf);
                continue;
            }

            if (!target.is_getter && memcmp(proto_stolen, expected_prologue,
                       sizeof(expected_prologue)) != 0)
            {
                char buf[128];
                snprintf(buf, sizeof(buf),
                         "Unexpected prologue for %s — RVA may have changed.",
                         target.name);
                Log::Warn(buf);
                continue;
            }

            vector<uint8_t> proto_sc;
            if (target.is_getter) {
                proto_sc = BuildGetHwidHookShellcode(proto_seed_addr);
            } else {
                uintptr_t proto_return = hook_addr + PROTO_STOLEN;
                proto_sc = BuildProtobufHwidHookShellcode(
                    proto_stolen, PROTO_STOLEN, proto_return, proto_seed_addr);
            }

            Log::Debug("Protobuf hook shellcode size", proto_sc.size());

            uintptr_t proto_tramp = (uintptr_t)trampoline + tramp_offset;

            if (!WriteProcessMemory(hprocess, (LPVOID)proto_tramp,
                                    proto_sc.data(), proto_sc.size(), &written)
                || written != proto_sc.size())
            {
                char buf[128];
                snprintf(buf, sizeof(buf),
                         "Failed to write shellcode for %s.", target.name);
                Log::Error(buf);
                continue;
            }

            tramp_offset += proto_sc.size();
            tramp_offset = (tramp_offset + 15) & ~(size_t)15;

            // 14-byte abs jmp, then nop pad whatever is left.
            uint8_t proto_patch[20];
            proto_patch[0] = 0xFF;
            proto_patch[1] = 0x25;
            proto_patch[2] = proto_patch[3] = proto_patch[4] = proto_patch[5] = 0x00;
            for (int i = 0; i < 8; ++i)
                proto_patch[6 + i] = (uint8_t)(proto_tramp >> (i * 8));
            memset(proto_patch + 14, 0x90, 6);

            DWORD pprot = 0;
            if (!VirtualProtectEx(hprocess, (LPVOID)hook_addr,
                                  PROTO_STOLEN, PAGE_EXECUTE_READWRITE, &pprot))
            {
                char buf[128];
                snprintf(buf, sizeof(buf),
                         "VirtualProtectEx failed for %s.", target.name);
                Log::Error(buf);
                continue;
            }

            if (WriteProcessMemory(hprocess, (LPVOID)hook_addr,
                                   proto_patch, PROTO_STOLEN, &written)
                && written == PROTO_STOLEN)
            {
                VirtualProtectEx(hprocess, (LPVOID)hook_addr,
                                 PROTO_STOLEN, pprot, &pprot);
                FlushInstructionCache(hprocess, (LPCVOID)hook_addr,
                                      PROTO_STOLEN);
                ++proto_hooks_installed;
                char buf[128];
                snprintf(buf, sizeof(buf),
                         "%s hooked (hwid + hwid2 pre-spoof).", target.name);
                Log::Ok(buf);
            } else {
                VirtualProtectEx(hprocess, (LPVOID)hook_addr,
                                 PROTO_STOLEN, pprot, &pprot);
                char buf[128];
                snprintf(buf, sizeof(buf),
                         "Failed to patch %s.", target.name);
                Log::Error(buf);
            }
        }

        hwid_hooked_protobuf = (proto_hooks_installed > 0);
        if (proto_hooks_installed == 3) {
            Log::Ok("All 3 HWID entry-point hooks installed.");
        } else if (proto_hooks_installed > 0) {
            char buf[128];
            snprintf(buf, sizeof(buf),
                     "Only %d HWID hooks installed — partial coverage.", proto_hooks_installed);
            Log::Warn(buf);
        } else {
            Log::Warn("No HWID entry-point hooks could be installed.");
            Log::Info("HWID protobuf fields (hwid/hwid2) won't be spoofed.");
        }
    } else {
        Log::Warn("libexitlag.dll not loaded — HWID protobuf hook skipped.");
        Log::Info("Ensure ExitLag.exe is running before the bypass.");
    }

    CloseHandle(hprocess);

    Log::Summary(gaa_hooked_exitlag, gaa_hooked_qt, concurrency_ok, spoofed_concurrency, hwid_hooked_protobuf);

    Log::SetColor(Log::DIM);
    cout << "  Press Enter to exit..." << endl;
    Log::SetColor(Log::RESET);
    std::cin.get();
    return 0;
}


/*
    this is the boring fix that actually sticks.
    exitlag leaves per-install identity junk outside the hwid json, so wipe it before relaunch.
*/

static void StopExitLagService()
{
    // programdata stays locked if the service is still around.
    system("sc stop ExitLagService       > nul 2>&1");
    system("sc stop ExitLag              > nul 2>&1");
    system("sc stop libexitlag           > nul 2>&1");
    system("sc stop ExitLagHelperService > nul 2>&1");
    Sleep(400);
}

static void KillExitLag()
{
    // give the gui/helper tree a few passes so handles actually drop.
    for (int pass = 0; pass < 8; ++pass) {
        DWORD pid = GetPIdByProcessName("ExitLag.exe");
        if (!pid) {
            DWORD pid2 = GetPIdByProcessName("libexitlag.exe");
            DWORD pid3 = GetPIdByProcessName("ExitLagService.exe");
            if (!pid2 && !pid3) break;
        }
        system("taskkill /F /T /IM ExitLag.exe           > nul 2>&1");
        system("taskkill /F /T /IM libexitlag.exe        > nul 2>&1");
        system("taskkill /F /T /IM ExitLagService.exe    > nul 2>&1");
        system("taskkill /F /T /IM ExitLagHelper.exe     > nul 2>&1");
        Sleep(250);
    }
}

static bool PathExists(const char* path)
{
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static void WipeDir(const char* path)
{
    if (!PathExists(path)) return;
    char cmd[MAX_PATH + 64];
    snprintf(cmd, sizeof(cmd), "rmdir /s /q \"%s\" > nul 2>&1", path);
    system(cmd);
    if (PathExists(path)) {
        // one retry helps when something is still unwinding.
        Sleep(200);
        system(cmd);
    }
    Log::Debug(path);
}

static void WipeRegistry(const char* hive_key)
{
    char cmd[MAX_PATH + 64];
    snprintf(cmd, sizeof(cmd), "reg delete \"%s\" /f > nul 2>&1", hive_key);
    system(cmd);
    Log::Debug(hive_key);
}

static void WipeFileGlob(const char* dir, const char* pattern)
{
    if (!PathExists(dir)) return;
    char cmd[MAX_PATH + 64];
    snprintf(cmd, sizeof(cmd), "del /f /q \"%s\\%s\" > nul 2>&1", dir, pattern);
    system(cmd);
}

static void WipePersistentIdentity()
{
    Log::Step("Wiping ExitLag persistent identifier cache");

    // service first, then the leftover userland stuff.
    StopExitLagService();
    KillExitLag();

    const char* roaming     = getenv("APPDATA");
    const char* local       = getenv("LOCALAPPDATA");
    const char* programdata = getenv("PROGRAMDATA");
    const char* userprofile = getenv("USERPROFILE");
    char buf[MAX_PATH];

    // user cache.
    if (roaming) {
        snprintf(buf, sizeof(buf), "%s\\ExitLag", roaming);    WipeDir(buf);
        snprintf(buf, sizeof(buf), "%s\\exitlag", roaming);    WipeDir(buf);
        WipeFileGlob(roaming, "exitlag.ini");
        WipeFileGlob(roaming, "ExitLag.ini");
    }
    if (local) {
        snprintf(buf, sizeof(buf), "%s\\ExitLag", local);      WipeDir(buf);
        snprintf(buf, sizeof(buf), "%s\\exitlag", local);      WipeDir(buf);
    }

    // system-wide cache. this is usually the sticky one.
    if (programdata) {
        snprintf(buf, sizeof(buf), "%s\\ExitLag", programdata); WipeDir(buf);
        snprintf(buf, sizeof(buf), "%s\\exitlag", programdata); WipeDir(buf);
    }

    // random leftovers under the profile.
    if (userprofile) {
        snprintf(buf, sizeof(buf), "%s\\Documents\\ExitLag", userprofile);
        WipeDir(buf);
    }

    // installer-side cache junk.
    const char* install_dirs[] = {
        "C:\\Program Files\\ExitLag",
        "C:\\Program Files (x86)\\ExitLag",
    };
    for (const char* dir : install_dirs) {
        if (!PathExists(dir)) continue;
        WipeFileGlob(dir, "*.db");
        WipeFileGlob(dir, "*.sqlite");
        WipeFileGlob(dir, "*.sqlite3");
        WipeFileGlob(dir, "*.ini");
        WipeFileGlob(dir, "*.dat");
        WipeFileGlob(dir, "client.log");
        snprintf(buf, sizeof(buf), "%s\\data",     dir); WipeDir(buf);
        snprintf(buf, sizeof(buf), "%s\\cache",    dir); WipeDir(buf);
        snprintf(buf, sizeof(buf), "%s\\config",   dir); WipeDir(buf);
        snprintf(buf, sizeof(buf), "%s\\settings", dir); WipeDir(buf);
    }

    // qt-style registry crumbs.
    WipeRegistry("HKCU\\Software\\ExitLag");
    WipeRegistry("HKCU\\Software\\exitlag");
    WipeRegistry("HKCU\\Software\\Lagarith");        // old org key seen in some builds.
    WipeRegistry("HKLM\\Software\\ExitLag");
    WipeRegistry("HKLM\\Software\\WOW6432Node\\ExitLag");
}


static void LaunchExitLag()
{
    if (GetPIdByProcessName("ExitLag.exe") != 0) return;

    FILE* fo = fopen("ExitLag.exe", "r");
    if (fo) {
        fclose(fo);
        system("@echo off & start ExitLag.exe");
        return;
    }
    fo = fopen("C:\\Program Files (x86)\\ExitLag\\ExitLag.exe", "r");
    if (fo) {
        fclose(fo);
        system("@echo off & start \"\" \"C:\\Program Files (x86)\\ExitLag\\ExitLag.exe\" > nul");
        return;
    }
    fo = fopen("C:\\Program Files\\ExitLag\\ExitLag.exe", "r");
    if (fo) {
        fclose(fo);
        system("@echo off & start \"\" \"C:\\Program Files\\ExitLag\\ExitLag.exe\" > nul");
        return;
    }
}


int main()
{
    setlocale(LC_ALL, "");
    SetConsoleTitleA("KaizerLag v2.0");

    // winapi resize keeps the banner buffer intact.
    {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        COORD bufSize = { 80, 500 };
        SetConsoleScreenBufferSize(hOut, bufSize);
        SMALL_RECT win = { 0, 0, 79, 39 };
        SetConsoleWindowInfo(hOut, TRUE, &win);
    }

    Log::SetColor(Log::RESET);
    Log::Banner();

    // wipe the sticky install id before booting exitlag again.
    WipePersistentIdentity();

    LaunchExitLag();

    return run_bypass();
}
