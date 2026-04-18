#pragma once

// Get the process id of the process, knowing the process name.
// const char* name -> the name of the process (ANSI).
// return DWORD -> the process identifier, or 0 if not found.
DWORD GetPIdByProcessName(const char* name)
{
	PROCESSENTRY32 PE32;
	PE32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return 0;

	if (!Process32First(hSnap, &PE32)) {
		CloseHandle(hSnap);
		return 0;
	}
	do {
		if (!_stricmp(PE32.szExeFile, name)) {
			CloseHandle(hSnap);
			return PE32.th32ProcessID;
		}
	} while (Process32Next(hSnap, &PE32));

	CloseHandle(hSnap);
	return 0;
}


// Get the base address of a module inside a target process.
// DWORD Pid           -> the process id of the target.
// const char* ModuleName -> the name of the module (e.g. "ExitLag.exe").
// return uintptr_t -> the module base address, or 0 if not found.
//
// NOTE: CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ...) can only enumerate
// modules with the same bitness as the caller. The bypass MUST be compiled as
// x64 (Platform=x64) for this to work against the current 64-bit ExitLag.
uintptr_t GetModuleAddressByName(DWORD Pid, const char* ModuleName) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, Pid);
	if (snapshot == INVALID_HANDLE_VALUE) return 0;

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(snapshot, &me32)) {
		CloseHandle(snapshot);
		return 0;
	}
	do {
		if (!_stricmp(me32.szModule, ModuleName)) {
			uintptr_t base = (uintptr_t)me32.modBaseAddr;
			CloseHandle(snapshot);
			return base;
		}
	} while (Module32Next(snapshot, &me32));

	CloseHandle(snapshot);
	return 0;
}


// Resolve the SizeOfImage for a loaded module by parsing its PE headers.
// Returns 0 on failure.
SIZE_T GetModuleImageSize(HANDLE hprocess, uintptr_t module_base) {
	IMAGE_DOS_HEADER dos{};
	SIZE_T read = 0;
	if (!ReadProcessMemory(hprocess, (LPCVOID)module_base, &dos, sizeof(dos), &read) || read != sizeof(dos))
		return 0;
	if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

	IMAGE_NT_HEADERS64 nt{};
	if (!ReadProcessMemory(hprocess, (LPCVOID)(module_base + dos.e_lfanew), &nt, sizeof(nt), &read) || read != sizeof(nt))
		return 0;
	if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

	return nt.OptionalHeader.SizeOfImage;
}


// Split a string by a delimiter.
vector<string> split(const string& s, char delimiter)
{
	vector<string> tokens;
	string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimiter))
	{
		tokens.push_back(token);
	}
	return tokens;
}

// "AA" -> 0xAA
BYTE StrHexToInt(string hex_byte_str) {
	return (BYTE)strtoul(hex_byte_str.c_str(), nullptr, 16);
}

// "AA BB ?? CC" -> bytes=[0xAA,0xBB,0x00,0xCC], mask="xx?x"
void PatternStringToBytePatternAndMask(string in_pattern, vector<byte>* out_pattern, string* out_mask) {
	vector<string> res = split(in_pattern, ' ');
	string mask;
	vector<byte> pattern_return;

	for (unsigned int x = 0; x < res.size(); x++) {
		if (res[x].empty()) continue;
		if (strcmp("??", res[x].c_str())) {
			mask += "x";
			pattern_return.push_back((byte)StrHexToInt(res[x]));
		}
		else {
			pattern_return.push_back(0);
			mask += "?";
		}
	}
	*out_pattern = pattern_return;
	*out_mask = mask;
}

// Pattern-scan an arbitrary virtual range in a target process.
// Walks committed pages via VirtualQueryEx and skips anything unreadable
// (PAGE_NOACCESS / PAGE_GUARD / uncommitted). No protection mutation.
//
// Returns the first match address, or 0 if not found.
uintptr_t ExPatternScanByStartAddress(HANDLE hprocess,
									  uintptr_t start_address,
									  SIZE_T section_size,
									  const vector<byte>& pattern,
									  const string& mask)
{
	if (pattern.empty()) return 0;

	const uintptr_t scan_end = start_address + section_size;
	std::vector<byte> buffer;

	uintptr_t cursor = start_address;
	while (cursor < scan_end) {
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQueryEx(hprocess, (LPCVOID)cursor, &mbi, sizeof(mbi))) break;

		uintptr_t region_base = (uintptr_t)mbi.BaseAddress;
		uintptr_t region_end = region_base + mbi.RegionSize;

		bool readable = (mbi.State == MEM_COMMIT) &&
			!(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));

		if (readable) {
			uintptr_t chunk_start = (cursor > region_base) ? cursor : region_base;
			uintptr_t chunk_end = (scan_end < region_end) ? scan_end : region_end;
			SIZE_T chunk_size = (SIZE_T)(chunk_end - chunk_start);

			buffer.assign(chunk_size, 0);
			SIZE_T bytes_read = 0;
			if (ReadProcessMemory(hprocess, (LPCVOID)chunk_start, buffer.data(), chunk_size, &bytes_read) && bytes_read > 0) {
				if (bytes_read >= pattern.size()) {
					const SIZE_T end_i = bytes_read - pattern.size();
					for (SIZE_T i = 0; i <= end_i; ++i) {
						bool ok = true;
						for (SIZE_T j = 0; j < pattern.size(); ++j) {
							if (mask[j] == '?') continue;
							if (buffer[i + j] != pattern[j]) { ok = false; break; }
						}
						if (ok) return chunk_start + i;
					}
				}
			}
		}

		if (region_end <= cursor) break; // guard against infinite loop
		cursor = region_end;
	}
	return 0;
}
