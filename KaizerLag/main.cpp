/*
    Made by: ALEHACKsp
    Improved by: kaizer1308
    Github:  https://github.com/ALEHACKsp/hwid-bypass

    x64 rewrite (ExitLag 5.20.x and later, which ships as a 64-bit binary).

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
    // Windows console color constants
    enum Color : WORD {
        RESET   = 0x07,  // light grey on black
        RED     = 0x0C,  // bright red
        GREEN   = 0x0A,  // bright green
        YELLOW  = 0x0E,  // bright yellow
        CYAN    = 0x0B,  // bright cyan
        DIM     = 0x08,  // dark grey
        WHITE   = 0x0F,  // bright white
        MAGENTA = 0x0D,  // bright magenta
    };

    static void SetColor(Color c) { SetConsoleTextAttribute(g_console, c); }

    // Core print with tag + color
    static void Print(Color tagColor, const char* tag, const char* msg) {
        cout << "  ";
        SetColor(tagColor);
        cout << tag << " ";
        SetColor(WHITE);
        cout << msg << endl;
        SetColor(RESET);
    }

    // --- Public API ---------------------------------------------------

    static void Error(const char* msg) {
        Print(RED, "[x]", msg);
    }

    static void Ok(const char* msg) {
        Print(CYAN, "[+]", msg);
    }

    static void Info(const char* msg) {
        Print(CYAN, "[-]", msg);
    }

    static void Warn(const char* msg) {
        Print(YELLOW, "[!]", msg);
    }

    static void Debug(const char* msg) {
        cout << "  ";
        SetColor(DIM);
        cout << "[~] " << msg << endl;
        SetColor(RESET);
    }

    static void Debug(const char* label, uintptr_t value) {
        cout << "  ";
        SetColor(DIM);
        cout << "[~] " << label << ": 0x" << hex << value << dec << endl;
        SetColor(RESET);
    }

    static void Step(const char* msg) {
        cout << endl;
        cout << "  ";
        SetColor(CYAN);
        cout << ":: ";
        SetColor(WHITE);
        cout << msg << endl;
        SetColor(RESET);
    }

    // Centered output helper
    static void PrintCentered(const char* text) {
        int len = (int)strlen(text);
        int pad = (80 - len) / 2;
        if (pad > 0) cout << std::string(pad, ' ');
        cout << text << endl;
    }

    // Blank line
    static void Spacer() { cout << endl; }

    // Branded banner
    static void Banner() {
        Spacer();
        SetColor(CYAN);
        PrintCentered(R"(   ____  __.      .__                    .____                  )");
        PrintCentered(R"(  |    |/ _|____  |__|_______ ___________|    |   _____     ____  )");
        PrintCentered(R"(  |      < \__  \ |  \___   // __ \_  __ \    |   \__  \   / ___\ )");
        PrintCentered(R"(  |    |  \ / __ \|  |/    /\  ___/|  | \/    |___ / __ \_/ /_/  >)");
        PrintCentered(R"(  |____|__ (____  /__/_____ \\___  >__|  |_______ (____  /\___  / )");
        PrintCentered(R"(          \/    \/         \/    \/              \/    \//_____/  )");
        Spacer();
        SetColor(DIM);
        PrintCentered("v2.0 - HWID Fingerprint Spoofer");
        SetColor(RESET);
        Spacer();
    }

    // Success summary box
    static void Summary(bool gaa_exitlag, bool gaa_qt, bool concurrency, uint32_t concurrency_val) {
        Spacer();
        SetColor(CYAN);
        cout << "  :: Spoofing Active" << endl;
        SetColor(RESET);

        auto Row = [](bool ok, const char* name, const char* detail) {
            SetColor(DIM);
            cout << "     ";
            SetColor(ok ? CYAN : DIM);
            cout << (ok ? "+" : "-");
            SetColor(WHITE);
            cout << " " << name;
            int pad = 24 - (int)strlen(name);
            for (int i = 0; i < pad; ++i) cout << ' ';
            SetColor(DIM);
            cout << detail << endl;
            SetColor(RESET);
        };

        Row(true,          "device_id",         "randomized wstring");
        Row(true,          "product_name",      "randomized wstring");
        Row(true,          "MACAddress",        "randomized wstring");
        Row(gaa_exitlag,   "macAddress (exe)",  "IAT hook");
        Row(gaa_qt,        "macAddress (Qt)",   "IAT hook");

        SetColor(DIM);
        cout << "     ";
        SetColor(concurrency ? CYAN : DIM);
        cout << (concurrency ? "+" : "-");
        SetColor(WHITE);
        cout << " concurrency             ";
        SetColor(DIM);
        if (concurrency)
            cout << "returns " << dec << concurrency_val << endl;
        else
            cout << "not patched" << endl;

        SetColor(RESET);
        Spacer();
        Ok("Ready. You can now log in with a new ExitLag account.");
        Spacer();
    }
}


/* ------------------------------------------------------------------
   FindIATEntry — Parse the PE import directory in a remote process
   to find the IAT slot for a specific function in a specific DLL.

   Returns the virtual address of the IAT slot, or 0 if not found.
   ------------------------------------------------------------------ */
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
        if (desc.Name == 0) break; // end of import table

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

                // Skip ordinal imports
                if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    continue;

                // Read the import name (2-byte Hint + null-terminated name)
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


/* ------------------------------------------------------------------
   BuildGAAHookShellcode — x64 shellcode that wraps GetAdaptersAddresses.

   When called (as IAT replacement):
     1. Forwards all 5 args to the real GetAdaptersAddresses.
     2. On success (return 0), walks the linked list of
        IP_ADAPTER_ADDRESSES and randomizes PhysicalAddress bytes.
     3. Returns original result.

   IP_ADAPTER_ADDRESSES x64 layout:
     +0x08  Next (pointer)
     +0x50  PhysicalAddress[8] (MAC bytes)
     +0x58  PhysicalAddressLength (ULONG)
   ------------------------------------------------------------------ */
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

    // Prolog: save non-volatile registers + allocate stack
    // Entry: rsp = X - 8 (call pushed ret addr)
    // After 2 pushes: rsp = X - 24
    // sub rsp, 0x28 (40): rsp = X - 64 → 16-byte aligned ✓
    emit({ 0x53 });                     // push rbx
    emit({ 0x56 });                     // push rsi
    emit({ 0x48, 0x83, 0xEC, 0x28 });   // sub rsp, 0x28

    // Save the 4th arg (r9 = pAdapterAddresses) in rsi
    emit({ 0x49, 0x8B, 0xF1 });         // mov rsi, r9

    // Forward 5th arg from caller's stack to our stack
    // Caller's 5th arg is at [rsp + 0x60] (after our prolog)
    // We put it at [rsp + 0x20] for the callee
    emit({ 0x48, 0x8B, 0x44, 0x24, 0x60 }); // mov rax, [rsp+0x60]
    emit({ 0x48, 0x89, 0x44, 0x24, 0x20 }); // mov [rsp+0x20], rax

    // Call real GetAdaptersAddresses (args still in rcx, rdx, r8, r9)
    emit({ 0x48, 0xB8 }); emit_u64(real_gaa_addr); // mov rax, <real_gaa>
    emit({ 0xFF, 0xD0 });               // call rax

    // Save return value in ebx
    emit({ 0x89, 0xC3 });               // mov ebx, eax

    // If not ERROR_SUCCESS (0), skip MAC randomization
    emit({ 0x85, 0xC0 });               // test eax, eax
    // jnz done (will patch offset later)
    size_t jnz_done_pos = sc.size();
    emit({ 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 }); // jnz rel32

    // Walk linked list starting at rsi (adapter buffer)
    emit({ 0x48, 0x8B, 0xCE });         // mov rcx, rsi  (rcx = current adapter)

    // walk_loop:
    size_t walk_loop_pos = sc.size();

    // test rcx, rcx ; jz done
    emit({ 0x48, 0x85, 0xC9 });         // test rcx, rcx
    size_t jz_done_pos = sc.size();
    emit({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 }); // jz rel32

    // Save rcx (current adapter) in r11 (non-volatile-ish, we own it)
    emit({ 0x49, 0x89, 0xCB });         // mov r11, rcx

    // Check PhysicalAddressLength ([rcx + 0x58]) >= 6
    emit({ 0x83, 0x79, 0x58, 0x06 });   // cmp dword [rcx+0x58], 6
    // jb next_adapter
    size_t jb_next_pos = sc.size();
    emit({ 0x72, 0x00 });               // jb rel8

    // Generate PRNG seed from RDTSC
    emit({ 0x0F, 0x31 });               // rdtsc
    emit({ 0x33, 0xC2 });               // xor eax, edx
    emit({ 0x0D, 0x01, 0x00, 0x00, 0x00 }); // or eax, 1
    emit({ 0x44, 0x8B, 0xD0 });         // mov r10d, eax  (r10d = prng state)

    // lea r8, [rcx + 0x50] → pointer to PhysicalAddress[0]
    emit({ 0x4C, 0x8D, 0x41, 0x50 });   // lea r8, [rcx+0x50]
    emit({ 0x41, 0xB9, 0x06, 0x00, 0x00, 0x00 }); // mov r9d, 6 (counter)

    // mac_loop:
    size_t mac_loop_pos = sc.size();
    emit({ 0x45, 0x69, 0xD2, 0x6D, 0x4E, 0xC6, 0x41 }); // imul r10d, r10d, 0x41C64E6D
    emit({ 0x41, 0x81, 0xC2, 0x39, 0x30, 0x00, 0x00 }); // add  r10d, 0x3039
    emit({ 0x41, 0x8B, 0xC2 });         // mov eax, r10d
    emit({ 0xC1, 0xE8, 0x10 });         // shr eax, 16
    emit({ 0x41, 0x88, 0x00 });         // mov [r8], al
    emit({ 0x49, 0xFF, 0xC0 });         // inc r8
    emit({ 0x41, 0xFF, 0xC9 });         // dec r9d
    // jnz mac_loop
    int32_t mac_delta = (int32_t)mac_loop_pos - (int32_t)(sc.size() + 2);
    emit({ 0x75, (uint8_t)(int8_t)mac_delta }); // jnz mac_loop

    // Fix locally-administered + unicast bits on first byte
    // and byte [rcx+0x50], 0xFE  (clear multicast bit)
    emit({ 0x80, 0x61, 0x50, 0xFE });   // and byte [rcx+0x50], 0xFE
    // or  byte [rcx+0x50], 0x02  (set locally-administered bit)
    emit({ 0x80, 0x49, 0x50, 0x02 });   // or  byte [rcx+0x50], 0x02

    // next_adapter:
    size_t next_adapter_pos = sc.size();
    int8_t jb_delta = (int8_t)((int32_t)next_adapter_pos - (int32_t)(jb_next_pos + 2));
    sc[jb_next_pos + 1] = (uint8_t)jb_delta;

    // Follow Next pointer: rcx = [r11 + 0x08]
    emit({ 0x49, 0x8B, 0x4B, 0x08 });   // mov rcx, [r11+0x08]
    // jmp walk_loop
    int32_t walk_delta = (int32_t)walk_loop_pos - (int32_t)(sc.size() + 5);
    emit({ 0xE9 }); emit_u32((uint32_t)walk_delta); // jmp walk_loop

    // done:
    size_t done_pos = sc.size();

    // Patch jnz_done offset
    int32_t jnz_done_delta = (int32_t)done_pos - (int32_t)(jnz_done_pos + 6);
    sc[jnz_done_pos + 2] = (uint8_t)(jnz_done_delta);
    sc[jnz_done_pos + 3] = (uint8_t)(jnz_done_delta >> 8);
    sc[jnz_done_pos + 4] = (uint8_t)(jnz_done_delta >> 16);
    sc[jnz_done_pos + 5] = (uint8_t)(jnz_done_delta >> 24);

    // Patch jz_done offset
    int32_t jz_done_delta = (int32_t)done_pos - (int32_t)(jz_done_pos + 6);
    sc[jz_done_pos + 2] = (uint8_t)(jz_done_delta);
    sc[jz_done_pos + 3] = (uint8_t)(jz_done_delta >> 8);
    sc[jz_done_pos + 4] = (uint8_t)(jz_done_delta >> 16);
    sc[jz_done_pos + 5] = (uint8_t)(jz_done_delta >> 24);

    // Restore return value
    emit({ 0x89, 0xD8 });               // mov eax, ebx

    // Epilog
    emit({ 0x48, 0x83, 0xC4, 0x28 });   // add rsp, 0x28
    emit({ 0x5E });                     // pop rsi
    emit({ 0x5B });                     // pop rbx
    emit({ 0xC3 });                     // ret

    return sc;
}


/* ------------------------------------------------------------------
   x64 shellcode generator for device_id / product_name / MACAddress
   randomization.

   The stolen instructions (the 7 bytes we overwrite at the hook site)
   are passed in as raw bytes and replayed verbatim. This means the
   shellcode automatically adapts to different compiler-chosen stack
   offsets (e.g. [rbp+0x27] vs [rbp+0x37]) across ExitLag versions.

   Layout produced:

       ; --- save volatiles ---
       push rax / rcx / rdx / r8 / r9 / r10 / r11 / r12

       ; --- PRNG-seed + randomize 3 x std::wstring fields ---
       (see inline comments below)

       ; --- restore volatiles ---
       pop r12..rax

       ; --- replay stolen instructions (7 bytes, read dynamically) ---
       <stolen_bytes[0..6]>               ; e.g. mov rdx,rbx; lea rcx,[rbp+??]
       mov rax, <fromStdWString IAT slot>
       call qword ptr [rax]

       ; --- absolute jump back past the hook window ---
       jmp qword ptr [rip+0]
       .qword <return_addr>
   ------------------------------------------------------------------ */
static vector<uint8_t> BuildShellcode(const uint8_t* stolen_bytes, size_t stolen_len,
                                      uintptr_t iat_slot, uintptr_t return_addr)
{
    vector<uint8_t> sc;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        sc.insert(sc.end(), bytes);
    };
    auto emit_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) sc.push_back((uint8_t)(v >> (i * 8)));
    };

    // Save volatile integer registers we will touch + r12 for our loop.
    emit({ 0x50 });                     // push rax
    emit({ 0x51 });                     // push rcx
    emit({ 0x52 });                     // push rdx
    emit({ 0x41, 0x50 });               // push r8
    emit({ 0x41, 0x51 });               // push r9
    emit({ 0x41, 0x52 });               // push r10
    emit({ 0x41, 0x53 });               // push r11
    emit({ 0x41, 0x54 });               // push r12

    // Seed PRNG globally for this run.
    emit({ 0x0F, 0x31 });                   // rdtsc
    emit({ 0x31, 0xD0 });                   // xor eax, edx
    emit({ 0x41, 0x89, 0xC2 });             // mov r10d, eax
    emit({ 0x41, 0x83, 0xCA, 0x01 });       // or  r10d, 1

    // We want to process 3 fields: device_id (0), product_name (0x20), MACAddress (0x40).
    emit({ 0x49, 0x8B, 0xDB });             // mov r11, rbx (r11 = current field ptr)
    emit({ 0x41, 0xBC, 0x03, 0x00, 0x00, 0x00 }); // mov r12d, 3 (loop counter)

    size_t outer_loop_pos = sc.size();

    // Resolve data pointer (r8 = data) for current field in r11.
    emit({ 0x4D, 0x83, 0x7B, 0x18, 0x08 }); // cmp qword [r11+0x18], 8
    emit({ 0x72, 0x06 });                   // jb  +6  -> .sso
    emit({ 0x4D, 0x8B, 0x03 });             // mov r8, [r11]
    emit({ 0xEB, 0x03 });                   // jmp +3  -> .have_ptr
    emit({ 0x4D, 0x8B, 0xC3 });             // .sso: mov r8, r11

    // r9 = size (wchar_t count).
    emit({ 0x4D, 0x8B, 0x4B, 0x10 });       // .have_ptr: mov r9, [r11+0x10]
    emit({ 0x4D, 0x85, 0xC9 });             // test r9, r9

    // jz .next_field
    size_t jz_pos = sc.size();
    emit({ 0x74, 0x00 });

    // LCG + store loop.
    size_t loop_pos = sc.size();
    emit({ 0x45, 0x69, 0xD2, 0x6D, 0x4E, 0xC6, 0x41 }); // imul r10d, r10d, 0x41C64E6D
    emit({ 0x41, 0x81, 0xC2, 0x39, 0x30, 0x00, 0x00 }); // add  r10d, 0x3039
    emit({ 0x41, 0x8B, 0xC2 });                         // mov  eax, r10d
    emit({ 0xC1, 0xE8, 0x10 });                         // shr  eax, 16
    emit({ 0x25, 0xFF, 0x7F, 0x00, 0x00 });             // and  eax, 0x7FFF
    emit({ 0x31, 0xD2 });                               // xor  edx, edx
    emit({ 0xB9, 0x0A, 0x00, 0x00, 0x00 });             // mov  ecx, 10
    emit({ 0xF7, 0xF1 });                               // div  ecx       ; edx = val % 10
    emit({ 0x80, 0xC2, 0x30 });                         // add  dl, '0' (randomize with numbers)
    emit({ 0x66, 0x41, 0x89, 0x10 });                   // mov  word [r8], dx
    emit({ 0x49, 0x83, 0xC0, 0x02 });                   // add  r8, 2
    emit({ 0x49, 0x83, 0xE9, 0x01 });                   // sub  r9, 1

    size_t jnz_pos = sc.size();
    int64_t jnz_delta = (int64_t)loop_pos - (int64_t)(jnz_pos + 2);
    emit({ 0x75, (uint8_t)(int8_t)jnz_delta });         // jnz .loop

    // .next_field:
    size_t next_field_pos = sc.size();
    int64_t jz_delta = (int64_t)next_field_pos - (int64_t)(jz_pos + 2);
    sc[jz_pos + 1] = (uint8_t)(int8_t)jz_delta;

    emit({ 0x49, 0x83, 0xC3, 0x20 });       // add r11, 0x20
    emit({ 0x41, 0x83, 0xEC, 0x01 });       // sub r12d, 1
    
    size_t outer_jnz_pos = sc.size();
    int64_t outer_jnz_delta = (int64_t)outer_loop_pos - (int64_t)(outer_jnz_pos + 2);
    emit({ 0x75, (uint8_t)(int8_t)outer_jnz_delta }); // jnz .outer_loop

    // Restore volatiles in reverse order.
    emit({ 0x41, 0x5C });               // pop r12
    emit({ 0x41, 0x5B });               // pop r11
    emit({ 0x41, 0x5A });               // pop r10
    emit({ 0x41, 0x59 });               // pop r9
    emit({ 0x41, 0x58 });               // pop r8
    emit({ 0x5A });                     // pop rdx
    emit({ 0x59 });                     // pop rcx
    emit({ 0x58 });                     // pop rax

    // Stolen-instruction replay — bytes read dynamically from the hook
    // site so we adapt to any compiler-chosen register/offset encoding.
    for (size_t i = 0; i < stolen_len; ++i)
        sc.push_back(stolen_bytes[i]);
    emit({ 0x48, 0xB8 });  emit_u64(iat_slot);  // mov rax, <iat_slot>
    emit({ 0xFF, 0x10 });                       // call qword ptr [rax]

    // Tail JMP back to host code, absolute via RIP-relative indirection.
    emit({ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }); // jmp qword ptr [rip+0]
    emit_u64(return_addr);

    return sc;
}


/* ------------------------------------------------------------------
   InstallIATHook — Replaces an IAT entry in the target process with
   a pointer to our wrapper shellcode. Returns true on success.
   ------------------------------------------------------------------ */
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

    // Read the real function pointer from the IAT slot
    uintptr_t real_func = 0;
    SIZE_T rd = 0;
    if (!ReadProcessMemory(hprocess, (LPCVOID)iat_slot, &real_func, sizeof(real_func), &rd) || rd != 8) {
        Log::Error("Failed to read real function pointer from IAT.");
        return false;
    }
    Log::Debug("Real function address", real_func);

    // Build the wrapper shellcode
    vector<uint8_t> sc = BuildGAAHookShellcode(real_func);
    Log::Debug("Wrapper shellcode size", sc.size());

    // Write wrapper to trampoline region at the given offset
    uintptr_t wrapper_addr = (uintptr_t)trampoline_region + offset;
    SIZE_T written = 0;
    if (!WriteProcessMemory(hprocess, (LPVOID)wrapper_addr, sc.data(), sc.size(), &written) || written != sc.size()) {
        Log::Error("Failed to write wrapper shellcode.");
        return false;
    }
    offset += sc.size();
    // Align to 16 bytes
    offset = (offset + 15) & ~(size_t)15;

    Log::Debug("Wrapper written at", wrapper_addr);

    // Overwrite the IAT slot with our wrapper address
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
    Log::Banner();

    // Track results for final summary
    bool gaa_hooked_exitlag = false;
    bool gaa_hooked_qt      = false;
    bool concurrency_ok     = false;
    uint32_t spoofed_concurrency = 0;


    // ---------------------------------------------------------------
    // 1. Find ExitLag.exe process
    // ---------------------------------------------------------------
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

    // Give ExitLag a moment to map its .text fully.
    Sleep(1000);

    // ---------------------------------------------------------------
    // 2. Get module base and image size
    // ---------------------------------------------------------------
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
        image_size = 0x08000000; // 128 MiB fallback
        Log::Debug("Using fallback image size (128 MiB)");
    }
    Log::Debug("Image size", image_size);

    // ---------------------------------------------------------------
    // 3. Allocate trampoline region (large enough for all hooks)
    // ---------------------------------------------------------------
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

    size_t tramp_offset = 0; // current write offset in the trampoline region

    // ---------------------------------------------------------------
    // 4. Install inline hook (device_id / product_name randomization)
    //    Uses a cascading pattern search: tries most-specific first,
    //    falls back to increasingly generic patterns so that minor
    //    recompilations (changed stack offsets) don't break the scan.
    // ---------------------------------------------------------------
    Log::Step("Installing device_id / product_name inline hook");

    // Pattern cascade — ordered most-specific to most-generic.
    // All patterns target the 3-byte "mov rdx, rbx" (48 8B D3) followed
    // by a 4-byte "lea rcx, [rbp+??]" and then the FF 15 IAT call.
    // The rbp offset byte is wildcarded in fallback patterns.
    const char* patterns[] = {
        // P0: Full 28-byte anchor (v5.20.x exact match)
        "48 8B D3 48 8D 4D 27 FF 15 ?? ?? ?? ?? 90 "
        "48 8B D0 48 8D 4D CF FF 15 ?? ?? ?? ?? 90",

        // P1: 14-byte anchor with wildcarded rbp offset
        "48 8B D3 48 8D 4D ?? FF 15 ?? ?? ?? ?? 90",

        // P2: Even shorter — just the IAT call pattern for fromStdWString
        //     preceded by mov rdx, rbx. We verify via string ref after.
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
            { // format pattern match message
                char buf[64];
                snprintf(buf, sizeof(buf), "Pattern P%d matched.", pi);
                Log::Ok(buf);
            }
            break;
        }
        { // format pattern miss message
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

    // Read the stolen instructions (first 7 bytes: mov rdx,rbx + lea rcx,[rbp+??])
    // These are replayed verbatim in the shellcode so we adapt to any offset.
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

    // Compute the RIP-relative IAT slot for QString::fromStdWString
    // The FF 15 xx xx xx xx instruction starts at hook_addr + 7
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

    // Build shellcode — pass stolen bytes so they're replayed verbatim
    const uintptr_t return_addr = hook_addr + 14;
    vector<uint8_t> sc = BuildShellcode(stolen, STOLEN_LEN, iat_slot, return_addr);
    Log::Debug("Inline hook shellcode size", sc.size());

    if (sc.empty()) {
        Log::Error("BuildShellcode returned empty.");
        VirtualFreeEx(hprocess, trampoline, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        Sleep(5000);
        return 1;
    }

    // Write the shellcode to trampoline region
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
    tramp_offset = (tramp_offset + 15) & ~(size_t)15; // align

    Log::Debug("Inline hook shellcode @", inline_hook_addr);

    // Patch the hook site with JMP to our shellcode
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

    // ---------------------------------------------------------------
    // 5. Install GetAdaptersAddresses IAT hook in ExitLag.exe
    //    This randomizes MAC addresses at the WinAPI level, covering
    //    both the simplified HWID JSON and the detailed adapter JSON.
    // ---------------------------------------------------------------
    Log::Step("Installing GetAdaptersAddresses IAT hook (ExitLag.exe)");

    gaa_hooked_exitlag = InstallIATHook(
        hprocess, module_base,
        "IPHLPAPI.DLL", "GetAdaptersAddresses",
        trampoline, tramp_offset,
        "Hooking ExitLag.exe -> IPHLPAPI.DLL"
    );

    if (!gaa_hooked_exitlag) {
        // Also try lowercase
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

    // ---------------------------------------------------------------
    // 5b. Try to also hook GetAdaptersAddresses in Qt6Network.dll
    //     (Qt uses its own IAT entry to enumerate network interfaces)
    // ---------------------------------------------------------------
    Log::Step("Looking for Qt6Network.dll IAT hook");

    uintptr_t qt_net_base = GetModuleAddressByName(pid, "Qt6Network.dll");
    if (qt_net_base) {
        Log::Debug("Qt6Network.dll base", qt_net_base);

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

    // ---------------------------------------------------------------
    // 6. Patch _Thrd_hardware_concurrency to return a spoofed value.
    //    Found dynamically via IAT import name resolution from
    //    MSVCP140.dll — no hardcoded RVA needed.
    // ---------------------------------------------------------------
    Log::Step("Patching _Thrd_hardware_concurrency (IAT lookup)");

    // Resolve the function address dynamically through the IAT.
    // _Thrd_hardware_concurrency is imported by name from MSVCP140.dll.
    uintptr_t thrd_iat_slot = FindIATEntry(hprocess, module_base,
                                            "MSVCP140.dll", "_Thrd_hardware_concurrency");
    if (!thrd_iat_slot) {
        // Try alternate casing
        thrd_iat_slot = FindIATEntry(hprocess, module_base,
                                     "msvcp140.dll", "_Thrd_hardware_concurrency");
    }

    if (thrd_iat_slot) {
        // Read the resolved function pointer (where the actual code lives)
        uintptr_t thrd_hw_addr = 0;
        if (ReadProcessMemory(hprocess, (LPCVOID)thrd_iat_slot, &thrd_hw_addr, sizeof(thrd_hw_addr), &rd) && rd == 8 && thrd_hw_addr) {
            Log::Debug("_Thrd_hardware_concurrency resolved at", thrd_hw_addr);

            // Generate a plausible random thread count: 4, 6, 8, 12, or 16
            const uint32_t plausible_counts[] = { 4, 6, 8, 12, 16 };
            srand(GetTickCount());
            spoofed_concurrency = plausible_counts[rand() % 5];

            // Build patch: mov eax, <value>; ret (6 bytes)
            uint8_t concurrency_patch[6] = {
                0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, imm32
                0xC3                             // ret
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

    // ---------------------------------------------------------------
    // Done
    // ---------------------------------------------------------------
    CloseHandle(hprocess);

    Log::Summary(gaa_hooked_exitlag, gaa_hooked_qt, concurrency_ok, spoofed_concurrency);

    Log::SetColor(Log::DIM);
    cout << "  Press Enter to exit..." << endl;
    Log::SetColor(Log::RESET);
    std::cin.get();
    return 0;
}


int main()
{
    setlocale(LC_ALL, "");
    SetConsoleTitleA("KaizerLag v2.0");

    // Resize console without clearing (system("MODE ...") wipes the buffer).
    {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        COORD bufSize = { 80, 500 };   // 80 cols, 500-line scroll buffer
        SetConsoleScreenBufferSize(hOut, bufSize);
        SMALL_RECT win = { 0, 0, 79, 39 }; // 80 x 40 visible window
        SetConsoleWindowInfo(hOut, TRUE, &win);
    }

    Log::SetColor(Log::RESET);

    // Kick ExitLag if not running.
    if (GetPIdByProcessName("ExitLag.exe") == 0) {
        FILE* fo = fopen("ExitLag.exe", "r");
        if (fo) {
            fclose(fo);
            system("@echo off & start ExitLag.exe");
        }
        fo = fopen("C:\\Program Files (x86)\\ExitLag\\ExitLag.exe", "r");
        if (fo) {
            fclose(fo);
            if (GetPIdByProcessName("ExitLag.exe") == 0) {
                system("@echo off & start \"\" \"C:\\Program Files (x86)\\ExitLag\\ExitLag.exe\" > nul");
            }
        }
        fo = fopen("C:\\Program Files\\ExitLag\\ExitLag.exe", "r");
        if (fo) {
            fclose(fo);
            if (GetPIdByProcessName("ExitLag.exe") == 0) {
                system("@echo off & start \"\" \"C:\\Program Files\\ExitLag\\ExitLag.exe\" > nul");
            }
        }
    }

    return run_bypass();
}


/*
  -----------------------------------------------------------------
  Reference: target functions (from IDA)

  1) HWID JSON serializer (function referencing "device_id" string)
     Builds: { version, os, concurrency, network_adapters: [{device_id, product_name}] }
     Hook target for device_id / product_name randomization.

     The hook site is the first fromStdWString call inside the
     adapter loop. Pattern cascade finds it dynamically; stolen
     instructions (mov rdx,rbx + lea rcx,[rbp+??]) are read and
     replayed, so the exact [rbp+??] offset does not matter.

     "device_id"    <- rbx+0   (std::wstring)
     "product_name" <- rbx+32  (std::wstring)
     "MACAddress"   <- rbx+64  (std::wstring, not sent in this JSON)

  2) Detailed adapter JSON serializer
     Builds per-adapter: { index, name, device, macAddress, ... }
     The "macAddress" field reads PhysicalAddress from the WinAPI.
     Covered by the GetAdaptersAddresses IAT hook.

  3) _Thrd_hardware_concurrency (imported from MSVCP140.dll)
     Returns the CPU hardware thread count. Used for the "concurrency"
     field in the HWID JSON. Located dynamically via IAT resolution,
     then patched to return a spoofed value. No hardcoded RVA.

  MSVC std::basic_string<wchar_t> layout (32 bytes):
       off  0 : union { wchar_t _Buf[8]; wchar_t* _Ptr; }
       off 16 : size_t _Mysize
       off 24 : size_t _Myres      ; capacity < 8 -> SSO, else heap.
  -----------------------------------------------------------------
*/
