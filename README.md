# FrostLock-Injection / Thread-Hijacking

FrostLock-Injection / Thread-Hijacking is a freeze/thaw-based code injection technique that uses Windows Job Objects to temporarily freeze (suspend) a target process, inject shellcode, and then seamlessly resume (thaw) it.

Tested on:
- Windows 11
- Windows 10

# 1. Introduction

This whitepaper introduces a unique technique for code injection that leverages the freezing (suspension) and thawing (resuming) of a target process using Windows Job Objects. The idea came to me while experimenting with System Informer, where I noticed the functionality to freeze and resume processes.

By freezing a target process at the right moment, we can inject shellcode without encountering many of the typical issues associated with real-time injection methods, such as race conditions or timing problems. This approach offers an elegant alternative to traditional remote thread injection.

System Informer (formerly known as Process Hacker) served as a key source of insights during this investigation. While Microsoft does not officially document a Freeze API, an in-depth analysis of code and header files revealed that freezing a process is indeed possible through an internal information class called `JobObjectFreezeInformation`.

For those who prefer a more imaginative perspective (perhaps fans of **The Eminence in Shadow**): Imagine being able to control processes from the shadows, freezing and resuming them at will. But let’s keep it subtle onward to the technical details!

## 1.1 Proof of Concept

### 1.1.2 Freeze/Thaw Injection (Without PostThreadMessage)

Process Edge:

![Edge](https://github.com/user-attachments/assets/dfc742ca-773e-439a-9885-2901a9177b73)

Process Notepad (Triggering on Event):

**Shellcode execution on close:**

![Notepad_1_Without_OnClose](https://github.com/user-attachments/assets/2dcf4b44-1c30-4714-90b5-0f2fc59a22a6)


**Shellcode execution new tab:**

![Notepad_NewTab](https://github.com/user-attachments/assets/24edd46d-6ff8-4c5b-9197-c4ddbb902407)


### 1.1.3 Freeze/Thaw Injection (With PostThreadMessage)

**Notepad:**

![Notepad_PostThreadMessage](https://github.com/user-attachments/assets/3dce8e93-2f60-4150-951a-a6f6067ede61)


**SecurityHealthSystray:**

![SecurityHealthSystray](https://github.com/user-attachments/assets/ac82a4cc-7d93-41fa-907c-22f5bcb9b3cd)


# 1. 2 Compatibility with svchost.exe

Since processes like `svchost.exe` are commonly exploited in various attack scenarios, I decided to give it a try as well. Unfortunately, there are compatibility issues with some variants. I tested a few configurations and stumbled upon an interesting feature.

If you target certain `svchost.exe` processes, the payload gets executed after the user logs back in. This opens up several potential scenarios for use, but I'll leave the rest to your imagination. 

### Tested svchost.exe processes:

- **C:\WINDOWS\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc**
- **C:\WINDOWS\system32\svchost.exe -k LocalService -p -s NPSMSvc**

Demonstration:

https://github.com/user-attachments/assets/452a9b9a-9a23-48b4-acc5-bd0c5a24b9e3

---

# 2. Standard Code Injection (Classic Approach)

Before diving into the Freeze/Thaw approach, let’s briefly discuss the **typical code injection** method common in many penetration testing and attack tools.

### 2.1 Typical Steps

1. **Enumerate Processes**  
    Identify the target process (e.g., by PID or Name).
2. **Open Handle**  
    Use `OpenProcess(PROCESS_ALL_ACCESS, ...)` (or native APIs like `NtOpenProcess`).
3. **Allocate Memory**  
    Call `VirtualAllocEx` in the target process.
4. **Write Shellcode**  
    Transfer the shellcode via `WriteProcessMemory`.
5. **Change Memory Protection**  
    Use `VirtualProtectEx` (e.g., change from RW to RX).
6. **Create Remote Thread**  or **ResumeThread**
    Call a specific function to start execution at the shellcode entry point.

Although these steps are widespread, modern EDR solutions can often detect this classic pattern. Hence the motivation to explore **Freeze/Thaw Injection** for stealthier or more specialized scenarios.

---

# 3. Windows Job Objects and Freezing Processes

### 3.1 What Are Job Objects?

A _job object_ allows groups of processes to be managed as a unit. Job objects are namable, securable, sharable objects that control attributes of the processes associated with them. Operations performed on a job object affect all processes associated with the job object. Examples include enforcing limits such as working set size and process priority or terminating all processes associated with a job.

### 3.2 Research with Systeminformer

Systeminformer revealed that you can actually pause a process using `SetInformationJobObject` with an internal class called `JobObjectFreezeInformation`. Although there is no official Microsoft API for this, the _Systeminformer_ code references (and some Windows header definitions) show how to configure an internal structure to freeze or thaw a process.

### 3.3 Freeze/Thaw: Structure Overview

```c++

#define JobObjectFreezeInformation 18

typedef struct _JOBOBJECT_WAKE_FILTER
{
    ULONG HighEdgeFilter;
    ULONG LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, *PJOBOBJECT_WAKE_FILTER;

typedef struct _JOBOBJECT_FREEZE_INFORMATION
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG FreezeOperation : 1;
            ULONG FilterOperation : 1;
            ULONG SwapOperation   : 1;
            ULONG Reserved        : 29;
        };
    };
    BOOLEAN Freeze;
    BOOLEAN Swap;
    UCHAR Reserved0[2];
    JOBOBJECT_WAKE_FILTER WakeFilter;
} JOBOBJECT_FREEZE_INFORMATION, *PJOBOBJECT_FREEZE_INFORMATION;
```

This structure holds a `Freeze` flag that, when set to `TRUE`, suspends all threads within the job. Setting it back to `FALSE` resumes them.

---

# 4. Freeze/Thaw Injection: How It Works

Our technique reuses many of the same steps as classic code injection, but inserts a freeze phase before and an unfreeze phase after the shellcode injection.

### 4.1 Workflow / Steps

1. **Enter PID** or otherwise obtain the target PID.
2. **Open a Process Handle** via `OpenProcess(PROCESS_ALL_ACCESS, ...)`.
3. **Create a Job Object** (`CreateJobObject`) and assign the process (`AssignProcessToJobObject`).
4. **Freeze the Process**:
    - Initialize `JOBOBJECT_FREEZE_INFORMATION` with `FreezeOperation = 1` and `Freeze = TRUE`.
    - Call `SetInformationJobObject` ⇒ the process is fully paused.
5. **Allocate Memory** (`VirtualAllocEx`, RW).
6. **Write the Shellcode** (`WriteProcessMemory`).
7. **Change Memory Protection** (`VirtualProtectEx`, e.g., PAGE_EXECUTE_READ).
8. **Adjust the Main Thread’s Context** so its RIP/EIP points to the new shellcode.
9. **Thaw the Process** (`Freeze = FALSE`), allowing the main thread to continue execution from the shellcode address.



### 4.2 Practical Special Cases

#### 4.2.1 Immediate Execution in Chrome, Edge, etc.

Browsers like **Chrome** or **Edge** will usually resume their main thread instantly upon thaw. The shellcode runs almost immediately.

#### 4.2.2 Delayed Execution in Notepad, SecurityHealthSystray, etc.

Some GUI programs such as **Notepad** or certain system applications wait for user input or a specific event before truly resuming.

- For Notepad, the shellcode might only execute after you open a new tab, close Notepad, or trigger another GUI event.
- These programs often sit in a message loop waiting for input.


#### 4.2.3 PostThreadMessage for Immediate Trigger

If you need to **force** the target thread to continue right away (rather than waiting for user interaction), you can call **`PostThreadMessage`** on the main thread ID.

- This only works if the thread has an active message queue.
- Sending a dummy message (like `WM_NULL`) can jumpstart the loop, causing the thread to process events and continue execution in the shellcode.


#### 4.2.4 Alternative: CreateProcess and Execute at Close

Another intriguing approach involves launching the target process yourself (e.g., using `CreateProcess`) and delaying the code injection until the user closes the application. The shellcode could then be triggered by a final event such as `WM_CLOSE`. For instance, imagine the user being puzzled as to why Notepad or another process was launched (or is already running). Upon closing the application, the shellcode is executed, like a stealthy infiltration from the shadows. 

This functionality is not currently implemented in the code but could be relatively easily added to a custom proof-of-concept (PoC).

This approach could also be useful in **anti-analysis** or **sandbox evasion** scenarios. Since the shellcode is triggered only by specific user actions, such as closing Notepad or opening a new tab, it could bypass automated analysis environments that do not simulate such behaviors.

---

# 5. What Is a Message Queue?

### 5.1 Message Queue Functionality

Windows GUI threads typically have a **message queue**. Events such as mouse clicks, keystrokes, or system notifications are placed in this queue, and the thread processes them via `GetMessage` or `PeekMessage`.

### 5.2 PostThreadMessage and Requirements

With **`PostThreadMessage(threadId, Msg, wParam, lParam)`**, you can post a message directly into another thread’s queue.

- **Requirement**: The thread must already have a message queue. Otherwise, `PostThreadMessage` fails with `ERROR_INVALID_THREAD_ID`.
- When the target thread picks up the posted message, it processes the message and can exit a wait state, resuming the shellcode execution.

---

# 6. Conclusion

This Freeze/Thaw Injection technique shows how **Windows Job Objects** can serve more exotic purposes than just resource limiting. By freezing a process, we avoid timing and concurrency issues during code injection. Once the memory is allocated, the shellcode is written, and the thread context is set, we simply thaw the process, causing execution to jump to our injected code.

**However**, whether the injected code executes immediately or is delayed depends on how the target process handles incoming events. Apps like Chrome or Edge generally run the payload right away, whereas Notepad or certain system processes (e.g., SecurityHealthSystray.exe) might wait for user interaction or message processing. The solution is to either rely on the user to trigger an event or actively push a message (`PostThreadMessage`) to force execution.

---

# 7. Acknowledgments and Disclaimer

**Acknowledgments**

- **System Informer Team** for their open-source code that revealed the freeze mechanism.
- All the Windows reverse engineers who continue to explore and document hidden and undocumented structures.
- To the creators and mentors of the **MalDev Academy**, who have provided invaluable foundational knowledge as well as advanced topics. I am still learning and fully aware that I have much, much more to master.


**Disclaimer**  
This Whitepaper is for **educational and research purposes only**. The author and contributors assume no responsibility for misuse or damage caused by these techniques. Always comply with legal guidelines and use these methods only in authorized environments.
