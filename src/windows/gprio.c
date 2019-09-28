/*
 Copyright (c) 2019 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <gimxcommon/include/gerror.h>
#include <gimxlog/include/glog.h>
#include <gimxcommon/include/glist.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>

GLOG_INST(GLOG_NAME)

static struct {
    unsigned int clients; // keep track of how many clients called gprio_init without calling gprio_end
    DWORD_PTR affinitymask; // backup in gprio_init, restore in gprio_end
    unsigned int core; // the selected core, 0 means none (core 0 is never selected)
    DWORD pid; // process id
    DWORD tid; // thread id
    DWORD ppid; // parent process id
} state = {};

typedef struct _THREAD_BASIC_INFORMATION {
    LONG ExitStatus;
    PVOID TebBaseAddress;
    struct {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } ClientId;
    DWORD_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

static LONG (__stdcall *pNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG) = NULL;

/*
 * Import NtQueryInformationThread from ntdll.dll. Useful for getting thread affinity.
 */
void dllimport(void) __attribute__((constructor));
void dllimport(void) {

    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE) {
        PRINT_ERROR_GETLASTERROR("GetModuleHandle ntdll.dll");
        exit(-1);
    }
    pNtQueryInformationThread = (LONG (__stdcall *)(HANDLE, LONG, PVOID, ULONG, PULONG))(void (*)(void)) GetProcAddress(hNtdll,
            "NtQueryInformationThread");
    if (pNtQueryInformationThread == NULL) {
        PRINT_ERROR_GETLASTERROR("GetProcAddress NtQueryInformationThread");
        exit(-1);
    }
}

/*
 * Get thread affinity.
 */
BOOL GetThreadAffinityMask(HANDLE hThread, PDWORD_PTR lpThreadAffinityMask) {

    THREAD_BASIC_INFORMATION info = { 0 };
    LONG status = pNtQueryInformationThread(hThread, 0, &info, sizeof(info), NULL);
    if (status == 0) {
        *lpThreadAffinityMask = info.AffinityMask;
    }
    if (status != 0 && status != (LONG) STATUS_INVALID_HANDLE) {
        if (GLOG_LEVEL(GLOG_NAME,ERROR)) { \
          fprintf(stderr, "%s:%d %s: NtQueryInformationThread failed with error: 0x%lx\n", __FILE__, __LINE__, __func__, status); \
        }
    }
    return status == 0;
}

struct processinfo {
    HANDLE handle;
    DWORD pid;
    DWORD_PTR affinitymask;
    int set;
    GLIST_LINK(struct processinfo)
};

/*
 * Restore affinity to core to all processes that got affinity changed.
 */
static int restoreprocess(struct processinfo * info) {

    if (info->set) {

        DWORD_PTR processmask, systemmask;
        if (GetProcessAffinityMask(info->handle, &processmask, &systemmask) != 0) {

            processmask |= (1 << state.core);

            if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
                printf("process = %lu restore affinity 0x%Ix.\n", info->pid, processmask);
            }

            if (SetProcessAffinityMask (info->handle, processmask) == 0) {
                PRINT_ERROR_GETLASTERROR("SetProcessAffinityMask");
            }

        } else if (GetLastError() != ERROR_INVALID_HANDLE) {
            PRINT_ERROR_GETLASTERROR("GetProcessAffinityMask");
        }
    }

    CloseHandle(info->handle);

    GLIST_REMOVE(processinfos, info)

    free(info);

    return 1;
}

/*
 * This doubly linked list is used to hold process information.
 */
GLIST_INST(struct processinfo, processinfos, restoreprocess)

struct threadinfo {
    HANDLE handle;
    DWORD tid;
    DWORD pid;
    DWORD_PTR affinitymask;
    int set;
    GLIST_LINK(struct threadinfo)
};

/*
 * Restore affinity to core to all threads that got affinity changed.
 */
static int restorethread(struct threadinfo * info) {

    if (info->set) {

        DWORD_PTR threadAffinity;
        if (GetThreadAffinityMask(info->handle, &threadAffinity) != 0) {

            threadAffinity |= (1 << state.core);

            if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
                printf("thread = %lu restore affinity 0x%Ix.\n", info->tid, threadAffinity);
            }

            if (SetThreadAffinityMask(info->handle, threadAffinity) == 0) {
                PRINT_ERROR_GETLASTERROR("SetThreadAffinityMask");
            }

        } else if (GetLastError() != ERROR_INVALID_HANDLE) {
            PRINT_ERROR_GETLASTERROR("GetThreadAffinityMask");
        }
    }

    CloseHandle(info->handle);

    GLIST_REMOVE(threadinfos, info)

    free(info);

    return 1;
}

/*
 * This doubly linked list is used to hold thread information.
 */
GLIST_INST(struct threadinfo, threadinfos, restorethread)

/*
 * Check if current process has elevated privileges.
 */
int iselevated() {

    int ret = 0;

    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID group;
    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &group) == 0) {
        PRINT_ERROR_GETLASTERROR("AllocateAndInitializeSid");
    } else {
        BOOL ismember = FALSE;
        if (CheckTokenMembership(NULL, group, &ismember) == 0) {
            PRINT_ERROR_GETLASTERROR("CheckTokenMembership");
        } else {
            ret = (ismember == TRUE);
        }
        FreeSid(group);
    }

    return ret;
}

/*
 * Count cores and get highest one.
 */
void getcores(DWORD_PTR mask, unsigned int * count, int * highest) {
    *count = 0;
    *highest = -1;
    while (mask) {
        ++(*highest);
        if (mask & 0x1) {
            ++(*count);
        }
        mask = mask >> 1;
    }
}

/*
 * Select core that has the lowest number of exclusive affinities.
 */
int selectcore(DWORD_PTR mask, int highest) {

    int score[highest + 1];
    memset(score, 0x00, sizeof(score));

    struct threadinfo * thread;
    for (thread = GLIST_BEGIN(threadinfos); thread != GLIST_END(threadinfos); thread = thread->next) {

        unsigned int corecount = 0;
        int highestcore = -1;
        getcores(thread->affinitymask, &corecount, &highestcore);

        if (corecount == 1 && highestcore <= highest) {
            if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
                printf("thread = %lu has exclusive affinity to core %d\n", thread->tid, highestcore);
            }
            ++(score[highestcore]);
        }
    }

    int core = 0;
    int min = 0;

    int j;
    for (j = 1; j <= highest; ++j) {
        if ((mask & (1 << j)) && score[j] <= min) {
            core = j;
        }
    }

    return core;
}

/*
 * Check if specified process has a thread with specific affinity.
 */
static int hasspecificaffinities(DWORD processid, DWORD_PTR processAffinity) {

    struct threadinfo * thread;
    for (thread = GLIST_BEGIN(threadinfos); thread != GLIST_END(threadinfos); thread = thread->next) {

        if (thread->pid == processid && thread->affinitymask != processAffinity) {
            return 1;
        }
    }

    return 0;
}

/*
 * Only keep info about processes that got affinity changed.
 */
static void cleanprocesses() {

    struct processinfo * process;
    for (process = GLIST_BEGIN(processinfos); process != GLIST_END(processinfos); process = process->next) {

        if (process->set == 0) {
            struct processinfo * prev = process->prev;
            CloseHandle(process->handle);
            GLIST_REMOVE(processinfos, process)
            free(process);
            process = prev;
        }
    }
}

/*
 * Get info about all running processes. Also get our parent process id.
 */
static void getprocessinfo() {

    HANDLE processes = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processes == INVALID_HANDLE_VALUE) {
        PRINT_ERROR_GETLASTERROR("CreateToolhelp32Snapshot");
        return;
    }

    PROCESSENTRY32 entry = { .dwSize = sizeof(entry) };
    if (!Process32First(processes, &entry)) {
        PRINT_ERROR_GETLASTERROR("Process32First");
        CloseHandle(processes);
        return;
    }

    do {

        if (entry.th32ProcessID == state.pid) {
            state.ppid = entry.th32ParentProcessID;
        }

        HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, entry.th32ProcessID);
        if (hprocess == INVALID_HANDLE_VALUE) {
            PRINT_ERROR_GETLASTERROR("OpenProcess");
            continue;
        }
        DWORD_PTR processmask, systemmask;
        if (GetProcessAffinityMask(hprocess, &processmask, &systemmask) == 0) {
            if (GetLastError() != ERROR_INVALID_HANDLE) {
                PRINT_ERROR_GETLASTERROR("GetProcessAffinityMask");
            }
            CloseHandle(hprocess);
            continue;
        }

        struct processinfo * info = malloc(sizeof(*info));
        if (info == NULL) {
            PRINT_ERROR_ALLOC_FAILED("malloc");
            CloseHandle(hprocess);
            continue;
        }

        info->handle = hprocess;
        info->pid = entry.th32ProcessID;
        info->affinitymask = processmask;
        info->set = 0;
        GLIST_ADD(processinfos, info)

    } while (Process32Next(processes, &entry));

    CloseHandle(processes);
}

/*
 * Unset affinities to specified core for all processes except:
 * - the current one
 * - its parent
 * - processes that have specific thread affinities
 *
 * Not changing parent process can help recovering affinities after a crash,
 * and parent process is probably just waiting for our termination.
 */
static void unsetprocessaffinities(unsigned int core) {

    struct processinfo * process;
    for (process = GLIST_BEGIN(processinfos); process != GLIST_END(processinfos); process = process->next) {

        if (process->pid == state.pid || process->pid == state.ppid) {
            continue;
        }

        if (hasspecificaffinities(process->pid, process->affinitymask)) {

            if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
                printf("process = %lu has a thread with specific affinity\n", process->pid);
            }
            continue;
        }

        DWORD_PTR affinitymask = process->affinitymask & ~(1 << core);

        // do not check (affinitymask != process->affinitymask) to help recovering after a crash

        if (affinitymask != 0) {

            if (SetProcessAffinityMask (process->handle, affinitymask) == 0) {
                PRINT_ERROR_GETLASTERROR("SetProcessAffinityMask");
                continue;
            }

            process->set = 1;
            if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
                printf("process = %lu set affinity 0x%Ix\n", process->pid, affinitymask);
            }
        }
    }
}

/*
 * Only keep info about threads that got affinity changed.
 */
static void cleanthreads() {

    struct threadinfo * thread;
    for (thread = GLIST_BEGIN(threadinfos); thread != GLIST_END(threadinfos); thread = thread->next) {

        if (thread->set == 0) {
            struct threadinfo * prev = thread->prev;
            CloseHandle(thread->handle);
            GLIST_REMOVE(threadinfos, thread)
            free(thread);
            thread = prev;
        }
    }
}

/*
 * Get info about all running threads.
 */
static void getthreadinfo() {

    HANDLE threads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (threads == INVALID_HANDLE_VALUE) {
        PRINT_ERROR_GETLASTERROR("CreateToolhelp32Snapshot");
        return;
    }

    THREADENTRY32 entry = { .dwSize = sizeof(entry) };
    if (!Thread32First(threads, &entry)) {
        PRINT_ERROR_GETLASTERROR("Thread32First");
        CloseHandle(threads);
        return;
    }

    do {

        HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, FALSE, entry.th32ThreadID);
        if (thread == INVALID_HANDLE_VALUE) {
            PRINT_ERROR_GETLASTERROR("OpenThread");
            continue;
        }

        DWORD_PTR threadAffinity;

        if (GetThreadAffinityMask(thread, &threadAffinity) == 0) {
            CloseHandle(thread);
            continue;
        }

        struct threadinfo * info = malloc(sizeof(*info));
        if (info == NULL) {
            PRINT_ERROR_ALLOC_FAILED("malloc");
            CloseHandle(thread);
            continue;
        }

        info->handle = thread;
        info->tid = entry.th32ThreadID;
        info->pid = entry.th32OwnerProcessID;
        info->affinitymask = threadAffinity;
        info->set = 0;
        GLIST_ADD(threadinfos, info)

    } while (Thread32Next(threads, &entry));

    CloseHandle(threads);
}

/*
 * Unset affinities to core for all threads in the current process, except the current one.
 */
static void unsetthreadaffinities(unsigned int core) {

    struct threadinfo * thread;
    for (thread = GLIST_BEGIN(threadinfos); thread != GLIST_END(threadinfos); thread = thread->next) {

        if (thread->pid != state.pid || thread->tid == state.tid) {
            continue;
        }

        DWORD_PTR threadAffinity = thread->affinitymask & ~(1 << core);

        if (threadAffinity == 0) {
            continue;
        }

        if (SetThreadAffinityMask(thread->handle, threadAffinity) == 0) {
            PRINT_ERROR_GETLASTERROR("SetThreadAffinityMask");
            continue;
        }

        thread->set = 1;
        if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
            printf("thread id = %lu set affinity 0x%Ix\n", thread->tid, threadAffinity);
        }
    }
}

/*
 * Set highest priority class.
 */
int sethighestpriorityclass() {

    if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
        printf("Set thread priority class to realtime.\n");
    }

    if (!SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS)) {
        PRINT_ERROR_GETLASTERROR("SetPriorityClass");
        return -1;
    }

    return 0;
}

/*
 * Set highest priority within our priority class.
 */
int sethighestpriority() {

    if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
        printf("Set thread priority to realtime.\n");
    }

    if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL)) {
        PRINT_ERROR_GETLASTERROR("SetThreadPriority");
        return -1;
    }

    return 0;
}

void gprio_clean() {

    if (state.clients > 0) {
        --state.clients;
    }

    if (state.clients > 0) {
        return;
    }

    if (state.core > 0) {

        GLIST_CLEAN_ALL(threadinfos, restorethread)

        GLIST_CLEAN_ALL(processinfos, restoreprocess)

        state.core = 0;
    }

    if (state.affinitymask != 0) {

        // Restore thread affinity to process affinity.

        DWORD_PTR process = 0, system = 0;
        if (GetProcessAffinityMask(GetCurrentProcess(), &process, &system) == 0) {
            PRINT_ERROR_GETLASTERROR("GetProcessAffinityMask");
        }

        if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
            printf("Restore thread affinity to 0x%Ix.\n", process);
        }

        if (SetThreadAffinityMask(GetCurrentThread(), process) == 0) {
            PRINT_ERROR_GETLASTERROR("SetThreadAffinityMask");
        }

        state.affinitymask = 0;
    }
}

int gprio_init() {

    if (state.clients == UINT_MAX) {
        PRINT_ERROR_OTHER("too many clients");
        return -1;
    }

    ++state.clients;

    if (state.clients > 1) {
        return 0;
    }

    state.pid = GetCurrentProcessId();
    state.tid = GetCurrentThreadId();

    DWORD_PTR processmask = 0, systemmask = 0;
    if (GetProcessAffinityMask(GetCurrentProcess(), &processmask, &systemmask) == 0) {
        PRINT_ERROR_GETLASTERROR("GetProcessAffinityMask");
        gprio_clean();
        return -1;
    }

    if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
        printf("Affinities: process = 0x%Ix, system = 0x%Ix\n", processmask, systemmask);
    }

    unsigned int corecount = 0;
    int highestcore = -1;
    getcores(processmask, &corecount, &highestcore);

    if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
        printf("Available cores = %u, highest = %d\n", corecount, highestcore);
    }

    // Never set highest priority class or change core affinities
    // if process is only allowed to run on a single core.

    if (iselevated() && corecount > 1) {

        if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
            printf("Thread has elevated privileges.\n");
        }

        if (sethighestpriorityclass() < 0) {
            gprio_clean();
            return -1;
        }

        getprocessinfo();
        getthreadinfo();

        int core = selectcore(processmask, highestcore);

        // Never set affinity to core 0 as a safety measure.

        if (core > 0) {

            if (GLOG_LEVEL(GLOG_NAME,DEBUG)) {
                printf("Set thread affinity to core %d.\n", core);
            }

            state.affinitymask = SetThreadAffinityMask(GetCurrentThread(), (1 << core));
            if (state.affinitymask == 0) {
                PRINT_ERROR_GETLASTERROR("SetThreadAffinityMask");
                gprio_clean();
                return -1;
            }

            state.core = core;

            unsetprocessaffinities(core);

            unsetthreadaffinities(core);
        }

        cleanprocesses();
        cleanthreads();
    }

    if (sethighestpriority() < 0) {
        gprio_clean();
        return -1;
    }

    return 0;
}
