# KaizerLag

x64 memory-hooking tool that spoofs hardware fingerprints on the fly to bypass ExitLag's 3-day trial limit.
Based on the original work by [ALEHACKsp](https://github.com/ALEHACKsp/hwid-bypass).

## Technical Overview

The original bypass only hooked one serializer path (`sub_1400AF400`). ExitLag still pulled your actual MAC address and CPU concurrency via a secondary serializer (`sub_14037B910`), leaking the real HWID. I added a multi-vector approach to plug these holes:

- **Inline Hook:** Replaces the `QString::fromStdWString` call site in `sub_1400AF400` to spoof adapter strings (`device_id` & `product_name`).
- **IAT Hook:** Intercepts `GetAdaptersAddresses` in both `ExitLag.exe` and `Qt6Network.dll`. This hijacks the WinAPI before Qt even reads it, fully randomizing the MAC address on all paths.
- **Byte Patching:** Overwrites `_Thrd_hardware_concurrency` (RVA `0x124FDB4`) with a quick `mov eax, N; ret` to randomize the CPU thread count.

## Usage

1. Compile `KaizerLag.sln` as **Release | x64** (v143 toolset). You must compile in x64 or process enumeration will fail against the 64-bit target.
2. Run `KaizerLag.exe` as Administrator. It will automatically boot ExitLag.
3. Log in with a fresh temp email. Trial activates automatically.

Everything happens entirely in memory at runtime. No permanent registry or hardware changes are made. If ExitLag updates and the hook breaks, just throw it in IDA and grab the new `fromStdWString` anchor pattern.

*Disclaimer: For educational RE research. Use responsibly.*
