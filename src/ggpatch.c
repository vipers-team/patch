/*
 * ggpatch.c - the loader / controller.
 *
 * Launches bin\launcher.exe under control, injects the 32-bit hook into it,
 * then waits for launcher.exe to spawn GGnet.exe and injects the 64-bit hook.
 *
 * Usage:  ggpatch.exe [bin_dir] [--block-loki]
 *   bin_dir      directory containing launcher.exe (default: ggpatch.exe dir)
 *   --block-loki reject Loki.dll / Loai.dll loads (may break the game)
 */
#include "ggpatch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HANDLE     g_map = NULL;
static GP_CONFIG *g_cfg_map = NULL;
static HANDLE     g_child_event = NULL;
static HANDLE     g_done_event = NULL;
static DWORD      g_injected64_pid = 0;

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */
static wchar_t *gp_utf8_to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = (wchar_t *)malloc(sizeof(wchar_t) * n);
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static void gp_dir_of(wchar_t *out, size_t cap, const wchar_t *full) {
    wcsncpy(out, full, cap);
    out[cap - 1] = 0;
    wchar_t *slash = wcsrchr(out, L'\\');
    if (slash) *(slash + 1) = 0; else out[0] = 0;
}

/* ------------------------------------------------------------------ */
/* Remote kernel32!LoadLibraryW resolution (cross-bitness safe)        */
/* ------------------------------------------------------------------ */
static BOOL gp_rpm(HANDLE proc, ULONG_PTR addr, void *buf, size_t n) {
    SIZE_T rd = 0;
    return ReadProcessMemory(proc, (LPCVOID)addr, buf, n, &rd) && rd == n;
}

typedef struct _GP_EXPORT_DIR {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} GP_EXPORT_DIR;

static ULONG_PTR gp_find_remote_loadlibrary(HANDLE proc, DWORD pid, BOOL is32) {
    /* 1. find kernel32.dll base in the target via Toolhelp */
    ULONG_PTR k32base = 0;
    DWORD flags = is32 ? TH32CS_SNAPMODULE32 : TH32CS_SNAPMODULE;
    HANDLE snap = CreateToolhelp32Snapshot(flags, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            if (gp_wcsicmp(me.szModule, L"kernel32.dll") == 0) {
                k32base = (ULONG_PTR)me.modBaseAddr;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    if (!k32base) return 0;

    /* 2. parse PE headers remotely */
    BYTE dos[0x40];
    if (!gp_rpm(proc, k32base, dos, sizeof(dos))) return 0;
    DWORD e_lfanew = *(DWORD *)(dos + 0x3C);

    BYTE nth[0x100];
    if (!gp_rpm(proc, k32base + e_lfanew, nth, sizeof(nth))) return 0;

    WORD magic = *(WORD *)(nth + 24);   /* FileHeader(20) after signature(4) */
    BOOL pe32 = (magic == 0x10B);

    /* export directory is DataDirectory[0] */
    DWORD dd_off = 24 + (pe32 ? 96 : 112);   /* within the NT headers copy */
    DWORD exp_rva = *(DWORD *)(nth + dd_off);
    DWORD exp_size = *(DWORD *)(nth + dd_off + 4);
    if (!exp_rva || !exp_size) return 0;

    GP_EXPORT_DIR ed;
    if (!gp_rpm(proc, k32base + exp_rva, &ed, sizeof(ed))) return 0;
    if (ed.NumberOfNames == 0 || ed.NumberOfNames > 0x10000) return 0;

    /* read the name pointer array */
    DWORD *names = (DWORD *)malloc(sizeof(DWORD) * ed.NumberOfNames);
    if (!names) return 0;
    if (!gp_rpm(proc, k32base + ed.AddressOfNames, names, sizeof(DWORD) * ed.NumberOfNames)) {
        free(names); return 0;
    }

    ULONG_PTR result = 0;
    DWORD i;
    for (i = 0; i < ed.NumberOfNames; i++) {
        char namebuf[64];
        if (!gp_rpm(proc, k32base + names[i], namebuf, sizeof(namebuf))) continue;
        namebuf[63] = 0;
        if (gp_stricmp(namebuf, "LoadLibraryW") == 0) {
            WORD ordinal;
            DWORD func_rva;
            if (!gp_rpm(proc, k32base + ed.AddressOfNameOrdinals + i * sizeof(WORD), &ordinal, sizeof(ordinal))) break;
            if (!gp_rpm(proc, k32base + ed.AddressOfFunctions + (DWORD)ordinal * sizeof(DWORD), &func_rva, sizeof(func_rva))) break;
            result = k32base + func_rva;
            break;
        }
    }
    free(names);
    return result;
}

static BOOL gp_inject(DWORD pid, const wchar_t *dll_path, BOOL is32) {
    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                              PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                              FALSE, pid);
    if (!proc) {
        printf("[GGnetPatch] OpenProcess(%lu) failed\n", (unsigned long)pid);
        return FALSE;
    }

    ULONG_PTR llw = gp_find_remote_loadlibrary(proc, pid, is32);
    if (!llw) {
        printf("[GGnetPatch] could not resolve LoadLibraryW in pid %lu\n", (unsigned long)pid);
        CloseHandle(proc);
        return FALSE;
    }

    size_t path_bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
    void *remote = VirtualAllocEx(proc, NULL, path_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { CloseHandle(proc); return FALSE; }

    SIZE_T written = 0;
    if (!WriteProcessMemory(proc, remote, dll_path, path_bytes, &written) || written != path_bytes) {
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc);
        return FALSE;
    }

    HANDLE thread = CreateRemoteThread(proc, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)llw, remote, 0, NULL);
    if (thread) {
        WaitForSingleObject(thread, 8000);
        CloseHandle(thread);
    }
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    CloseHandle(proc);
    return thread != NULL;
}

/* poll for a running GGnet.exe and inject the 64-bit hook once */
static void gp_poll_ggnet(const wchar_t *dll64) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (gp_wcsicmp(pe.szExeFile, L"GGnet.exe") == 0) {
                if (pe.th32ProcessID != g_injected64_pid) {
                    printf("[GGnetPatch] found GGnet.exe (pid %lu), injecting 64-bit hook\n",
                           (unsigned long)pe.th32ProcessID);
                    if (gp_inject(pe.th32ProcessID, dll64, FALSE)) {
                        g_injected64_pid = pe.th32ProcessID;
                    }
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    wchar_t self[MAX_PATH];
    wchar_t dir[MAX_PATH];
    wchar_t launcher[MAX_PATH];
    wchar_t dll32[MAX_PATH];
    wchar_t dll64[MAX_PATH];
    DWORD flags = GP_FLAG_ALL & ~GP_FLAG_BLOCK_LOKI;
    int i;

    GetModuleFileNameW(NULL, self, MAX_PATH);
    gp_dir_of(dir, MAX_PATH, self);

    /* optional bin dir argument */
    if (argc > 1 && argv[1][0] != '-') {
        wchar_t *w = gp_utf8_to_wide(argv[1]);
        if (w) {
            if (wcslen(w) && w[wcslen(w) - 1] != L'\\') wcscat(w, L"\\");
            wcsncpy(dir, w, MAX_PATH - 1); dir[MAX_PATH - 1] = 0;
            free(w);
        }
    }
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--block-loki") == 0) flags |= GP_FLAG_BLOCK_LOKI;
        if (strcmp(argv[i], "--no-cpuid") == 0) flags &= ~GP_FLAG_SPOOF_CPUID;
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("GGnetPatch - runtime VM spoofer for the GGnet client\n");
            printf("usage: ggpatch.exe [bin_dir] [--block-loki] [--no-cpuid]\n");
            return 0;
        }
    }

    _snwprintf(launcher, MAX_PATH, L"%slauncher.exe", dir);
    _snwprintf(dll32, MAX_PATH, L"%sgghook32.dll", dir);
    _snwprintf(dll64, MAX_PATH, L"%sgghook64.dll", dir);

    printf("[GGnetPatch] launcher: %ls\n", launcher);
    printf("[GGnetPatch] hook32:   %ls\n", dll32);
    printf("[GGnetPatch] hook64:   %ls\n", dll64);

    /* create shared config mapping + events */
    g_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(GP_CONFIG), GP_MAP_NAME);
    if (g_map) {
        g_cfg_map = (GP_CONFIG *)MapViewOfFile(g_map, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (g_cfg_map) {
            memset(g_cfg_map, 0, sizeof(*g_cfg_map));
            g_cfg_map->flags = flags;
            g_cfg_map->blockLoki = (flags & GP_FLAG_BLOCK_LOKI) ? 1 : 0;
        }
    }
    g_child_event = CreateEventW(NULL, FALSE, FALSE, GP_CHILD_EVENT);
    g_done_event  = CreateEventW(NULL, FALSE, FALSE, GP_DONE_EVENT);

    /* launch launcher.exe suspended */
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    BOOL ok = CreateProcessW(launcher, NULL, NULL, NULL, FALSE,
                             CREATE_SUSPENDED, NULL, dir, &si, &pi);
    if (!ok) {
        printf("[GGnetPatch] failed to launch launcher.exe (error %lu)\n",
               (unsigned long)GetLastError());
        return 1;
    }

    printf("[GGnetPatch] launcher.exe started (pid %lu), injecting 32-bit hook\n",
           (unsigned long)pi.dwProcessId);
    if (gp_inject(pi.dwProcessId, dll32, TRUE)) {
        printf("[GGnetPatch] 32-bit hook injected\n");
    } else {
        printf("[GGnetPatch] WARNING: 32-bit hook injection failed\n");
    }

    ResumeThread(pi.hThread);

    /* main loop: wait for GGnet.exe spawn, inject 64-bit hook */
    printf("[GGnetPatch] waiting for GGnet.exe...\n");
    for (;;) {
        DWORD w = WaitForSingleObject(g_child_event, 500);
        if (w == WAIT_OBJECT_0) {
            DWORD cpid = g_cfg_map ? g_cfg_map->childPid : 0;
            if (cpid) {
                printf("[GGnetPatch] child handshake: GGnet.exe pid %lu\n", (unsigned long)cpid);
                if (gp_inject(cpid, dll64, FALSE)) {
                    printf("[GGnetPatch] 64-bit hook injected\n");
                    g_injected64_pid = cpid;
                }
                SetEvent(g_done_event);
            }
        }
        gp_poll_ggnet(dll64);

        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
            printf("[GGnetPatch] launcher.exe exited\n");
            break;
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
