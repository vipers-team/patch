/*
 * gghook.c - the GGnet runtime spoofer.
 *
 * Compiled twice (32-bit and 64-bit) from the same source:
 *   - gghook32.dll  injected into launcher.exe (32-bit)
 *   - gghook64.dll  injected into GGnet.exe  (64-bit AIR runtime)
 *
 * It hooks the OS APIs the client uses to detect virtual machines and feeds
 * back clean values: process enumeration, CPUID, debugger flags, SMBIOS,
 * MAC addresses, registry, and (optionally) blocks Loki/Loai.
 */
#include "ggpatch.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Config + handshake                                                  */
/* ------------------------------------------------------------------ */
static GP_CONFIG g_cfg;
static HANDLE     g_map = NULL;
static GP_CONFIG *g_cfg_map = NULL;
static HANDLE     g_child_event = NULL;
static HANDLE     g_done_event = NULL;

static void gp_log(const char *s) { OutputDebugStringA(s); }

#define GP_SMBIOS_RSMB 0x52534D42 /* 'RSMB' */

static void gp_load_config(void) {
    g_cfg.flags = GP_FLAG_ALL & ~GP_FLAG_BLOCK_LOKI;
    g_cfg.blockLoki = 0;
    g_map = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, GP_MAP_NAME);
    if (g_map) {
        void *p = MapViewOfFile(g_map, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if (p) {
            memcpy(&g_cfg, p, sizeof(g_cfg));
            g_cfg_map = (GP_CONFIG *)p;
        }
    }
    g_child_event = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, GP_CHILD_EVENT);
    g_done_event  = OpenEventW(SYNCHRONIZE, FALSE, GP_DONE_EVENT);
}

static int gp_flag(DWORD f) { return (g_cfg.flags & f) != 0; }

/* ------------------------------------------------------------------ */
/* Original function pointers                                          */
/* ------------------------------------------------------------------ */
typedef BOOL    (WINAPI *t_IsDebuggerPresent)(void);
typedef BOOL    (WINAPI *t_CheckRemoteDebuggerPresent)(HANDLE, PBOOL);
typedef BOOL    (WINAPI *t_Process32FirstW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL    (WINAPI *t_Process32NextW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL    (WINAPI *t_Process32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL    (WINAPI *t_Process32Next)(HANDLE, LPPROCESSENTRY32);
typedef UINT    (WINAPI *t_GetSystemFirmwareTable)(DWORD, DWORD, PVOID, DWORD);
typedef DWORD   (WINAPI *t_GetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
typedef ULONG   (WINAPI *t_GetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
typedef LSTATUS (WINAPI *t_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *t_RegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef HMODULE (WINAPI *t_LoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI *t_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *t_LoadLibraryA)(LPCSTR);
typedef BOOL    (WINAPI *t_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL    (WINAPI *t_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef NTSTATUS (NTAPI *t_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

static t_IsDebuggerPresent          p_IsDebuggerPresent;
static t_CheckRemoteDebuggerPresent p_CheckRemoteDebuggerPresent;
static t_Process32FirstW            p_Process32FirstW;
static t_Process32NextW             p_Process32NextW;
static t_Process32First             p_Process32First;
static t_Process32Next              p_Process32Next;
static t_GetSystemFirmwareTable     p_GetSystemFirmwareTable;
static t_GetAdaptersInfo            p_GetAdaptersInfo;
static t_GetAdaptersAddresses       p_GetAdaptersAddresses;
static t_RegOpenKeyExW              p_RegOpenKeyExW;
static t_RegQueryValueExW           p_RegQueryValueExW;
static t_LoadLibraryW               p_LoadLibraryW;
static t_LoadLibraryExW             p_LoadLibraryExW;
static t_LoadLibraryA               p_LoadLibraryA;
static t_CreateProcessW             p_CreateProcessW;
static t_CreateProcessA             p_CreateProcessA;
static t_NtQuerySystemInformation   p_NtQuerySystemInformation;

static GP_HOOK g_hooks[32];
static int     g_hook_count = 0;

/* ------------------------------------------------------------------ */
/* Sanitizers                                                          */
/* ------------------------------------------------------------------ */
static void gp_sanitize_ascii(unsigned char *buf, size_t len) {
    static const char *const tok[] = {
        "vmware", "innotek", "qemu", "virtualbox", "seabios", "bhyve",
        "bochs", "ovmf", "xen", "parallels", "acrn", "microsoft corporation"
    };
    size_t i, t;
    for (i = 0; i < len; i++) {
        for (t = 0; t < sizeof(tok) / sizeof(tok[0]); t++) {
            const char *s = tok[t];
            size_t sl = strlen(s);
            if (i + sl <= len) {
                size_t k; int match = 1;
                for (k = 0; k < sl; k++) {
                    if (gp_tolower(buf[i + k]) != (unsigned char)s[k]) { match = 0; break; }
                }
                if (match) { for (k = 0; k < sl; k++) buf[i + k] = (unsigned char)' '; }
            }
        }
    }
}

static void gp_sanitize_wide(wchar_t *buf, size_t len) {
    static const wchar_t *const tok[] = {
        L"vmware", L"innotek", L"qemu", L"virtualbox", L"vbox", L"seabios",
        L"bhyve", L"bochs", L"ovmf", L"xen", L"parallels", L"acrn",
        L"microsoft corporation", L"kvm"
    };
    size_t i, t;
    for (i = 0; i < len; i++) {
        for (t = 0; t < sizeof(tok) / sizeof(tok[0]); t++) {
            const wchar_t *s = tok[t];
            size_t sl = wcslen(s);
            if (i + sl <= len) {
                size_t k; int match = 1;
                for (k = 0; k < sl; k++) {
                    wchar_t a = (wchar_t)gp_tolower((unsigned short)buf[i + k]);
                    wchar_t b = (wchar_t)gp_tolower((unsigned short)s[k]);
                    if (a != b) { match = 0; break; }
                }
                if (match) { for (k = 0; k < sl; k++) buf[i + k] = L' '; }
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Detours                                                             */
/* ------------------------------------------------------------------ */
static BOOL WINAPI d_IsDebuggerPresent(void) { return FALSE; }

static BOOL WINAPI d_CheckRemoteDebuggerPresent(HANDLE h, PBOOL pb) {
    if (pb) *pb = FALSE;
    return TRUE;
}

static BOOL WINAPI d_Process32FirstW(HANDLE h, LPPROCESSENTRY32W pe) {
    BOOL r = p_Process32FirstW(h, pe);
    while (r && gp_process_name_is_vm(pe->szExeFile)) r = p_Process32NextW(h, pe);
    return r;
}
static BOOL WINAPI d_Process32NextW(HANDLE h, LPPROCESSENTRY32W pe) {
    BOOL r;
    do { r = p_Process32NextW(h, pe); } while (r && gp_process_name_is_vm(pe->szExeFile));
    return r;
}
static BOOL WINAPI d_Process32First(HANDLE h, LPPROCESSENTRY32 pe) {
    BOOL r = p_Process32First(h, pe);
    while (r && gp_process_name_is_vm(pe->szExeFile)) r = p_Process32Next(h, pe);
    return r;
}
static BOOL WINAPI d_Process32Next(HANDLE h, LPPROCESSENTRY32 pe) {
    BOOL r;
    do { r = p_Process32Next(h, pe); } while (r && gp_process_name_is_vm(pe->szExeFile));
    return r;
}

static UINT WINAPI d_GetSystemFirmwareTable(DWORD table, DWORD id, PVOID buf, DWORD size) {
    UINT r = p_GetSystemFirmwareTable(table, id, buf, size);
    if (r && buf && (table == GP_SMBIOS_RSMB)) {
        gp_sanitize_ascii((unsigned char *)buf, r);
    }
    return r;
}

static void gp_fix_adapter_info(IP_ADAPTER_INFO *a) {
    for (; a; a = a->Next) {
        if (a->AddressLength >= 6 && gp_mac_is_vm(a->Address)) gp_rewrite_mac(a->Address);
        if (gp_text_is_vm(a->Description)) memset(a->Description, ' ', strlen(a->Description));
    }
}

static DWORD WINAPI d_GetAdaptersInfo(PIP_ADAPTER_INFO info, PULONG size) {
    DWORD r = p_GetAdaptersInfo(info, size);
    if (r == ERROR_SUCCESS && info) gp_fix_adapter_info(info);
    return r;
}

static ULONG WINAPI d_GetAdaptersAddresses(ULONG family, ULONG flags, PVOID reserved,
                                           PIP_ADAPTER_ADDRESSES a, PULONG size) {
    ULONG r = p_GetAdaptersAddresses(family, flags, reserved, a, size);
    if (r == NO_ERROR && a) {
        PIP_ADAPTER_ADDRESSES cur;
        for (cur = a; cur; cur = cur->Next) {
            if (cur->PhysicalAddressLength >= 6 && gp_mac_is_vm(cur->PhysicalAddress))
                gp_rewrite_mac(cur->PhysicalAddress);
            if (cur->Description && gp_wtext_is_vm(cur->Description))
                memset(cur->Description, ' ', wcslen(cur->Description) * sizeof(wchar_t));
            if (cur->FriendlyName && gp_wtext_is_vm(cur->FriendlyName))
                memset(cur->FriendlyName, ' ', wcslen(cur->FriendlyName) * sizeof(wchar_t));
        }
    }
    return r;
}

static LSTATUS WINAPI d_RegOpenKeyExW(HKEY root, LPCWSTR sub, DWORD opt, REGSAM sam, PHKEY out) {
    if (sub && gp_wcsistr(sub, L"vmware")) return ERROR_FILE_NOT_FOUND;
    if (sub && gp_wcsistr(sub, L"vbox")) return ERROR_FILE_NOT_FOUND;
    if (sub && gp_wcsistr(sub, L"virtualbox")) return ERROR_FILE_NOT_FOUND;
    if (sub && gp_wcsistr(sub, L"innotek")) return ERROR_FILE_NOT_FOUND;
    if (sub && gp_wcsistr(sub, L"qemu")) return ERROR_FILE_NOT_FOUND;
    return p_RegOpenKeyExW(root, sub, opt, sam, out);
}

static LSTATUS WINAPI d_RegQueryValueExW(HKEY key, LPCWSTR name, LPDWORD reserved,
                                         LPDWORD type, LPBYTE data, LPDWORD cb) {
    LSTATUS r = p_RegQueryValueExW(key, name, reserved, type, data, cb);
    if (r == ERROR_SUCCESS && data && type && cb) {
        if (*type == REG_SZ || *type == REG_EXPAND_SZ) {
            gp_sanitize_wide((wchar_t *)data, *cb / sizeof(wchar_t));
        } else if (*type == REG_MULTI_SZ) {
            gp_sanitize_wide((wchar_t *)data, *cb / sizeof(wchar_t));
        }
    }
    return r;
}

static HMODULE WINAPI d_LoadLibraryW(LPCWSTR name) {
    if (g_cfg.blockLoki && name) {
        const wchar_t *b = name;
        const wchar_t *slash = wcsrchr(name, L'\\');
        if (slash) b = slash + 1;
        if (gp_wcsicmp(b, L"loki.dll") == 0 || gp_wcsicmp(b, L"loai.dll") == 0) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            return NULL;
        }
    }
    return p_LoadLibraryW(name);
}

static HMODULE WINAPI d_LoadLibraryExW(LPCWSTR name, HANDLE f, DWORD flags) {
    if (g_cfg.blockLoki && name) {
        const wchar_t *b = name;
        const wchar_t *slash = wcsrchr(name, L'\\');
        if (slash) b = slash + 1;
        if (gp_wcsicmp(b, L"loki.dll") == 0 || gp_wcsicmp(b, L"loai.dll") == 0) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            return NULL;
        }
    }
    return p_LoadLibraryExW(name, f, flags);
}

static HMODULE WINAPI d_LoadLibraryA(LPCSTR name) {
    if (g_cfg.blockLoki && name) {
        const char *b = name;
        const char *slash = strrchr(name, '\\');
        if (slash) b = slash + 1;
        if (gp_stricmp(b, "loki.dll") == 0 || gp_stricmp(b, "loai.dll") == 0) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            return NULL;
        }
    }
    return p_LoadLibraryA(name);
}

/* ---- NtQuerySystemInformation (SystemProcessInformation) ---- */
#define SystemProcessInformation 5

typedef struct _GP_US {
    USHORT Length;
    USHORT MaximumLength;
#ifdef _WIN64
    DWORD  _pad;
    PWSTR  Buffer;
#else
    PWSTR  Buffer;
#endif
} GP_US;

typedef struct _GP_SPI {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    GP_US ImageName;
} GP_SPI;

static NTSTATUS NTAPI d_NtQuerySystemInformation(ULONG cls, PVOID info, ULONG len, PULONG retlen) {
    NTSTATUS st = p_NtQuerySystemInformation(cls, info, len, retlen);
    if (st == 0 && cls == SystemProcessInformation && info) {
        GP_SPI *cur = (GP_SPI *)info;
        for (;;) {
            if (cur->ImageName.Buffer && gp_process_name_is_vm(cur->ImageName.Buffer)) {
                cur->ImageName.Buffer[0] = 0;
                cur->ImageName.Length = 0;
            }
            if (cur->NextEntryOffset == 0) break;
            cur = (GP_SPI *)((unsigned char *)cur + cur->NextEntryOffset);
        }
    }
    return st;
}

/* ---- CreateProcess (child GGnet.exe suspension + handshake) ---- */
static int gp_is_ggnet_w(const wchar_t *s) {
    if (!s) return 0;
    const wchar_t *b = s;
    const wchar_t *slash = wcsrchr(s, L'\\');
    if (slash) b = slash + 1;
    const wchar_t *slash2 = wcsrchr(b, L'/');
    if (slash2) b = slash2 + 1;
    return gp_wcsicmp(b, L"ggnet.exe") == 0 || gp_wcsicmp(b, L"ggnet") == 0;
}

static BOOL WINAPI d_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES sa,
                                    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags,
                                    LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    int is_ggnet = gp_is_ggnet_w(app) || gp_is_ggnet_w(cmd);
    if (!is_ggnet) return p_CreateProcessW(app, cmd, sa, ta, inherit, flags, env, cwd, si, pi);

    DWORD nflags = flags | CREATE_SUSPENDED;
    BOOL r = p_CreateProcessW(app, cmd, sa, ta, inherit, nflags, env, cwd, si, pi);
    if (!r) return FALSE;

    if (g_cfg_map && pi) g_cfg_map->childPid = pi->dwProcessId;
    if (g_child_event) SetEvent(g_child_event);
    if (g_done_event) WaitForSingleObject(g_done_event, 15000);
    if (pi && pi->hThread) { ResumeThread(pi->hThread); }
    return TRUE;
}

static BOOL WINAPI d_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES sa,
                                    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags,
                                    LPVOID env, LPCSTR cwd, LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi) {
    int is_ggnet = 0;
    if (app) {
        const char *b = app; const char *s = strrchr(app, '\\');
        if (s) b = s + 1;
        is_ggnet = (gp_stricmp(b, "ggnet.exe") == 0 || gp_stricmp(b, "ggnet") == 0);
    }
    if (!is_ggnet && cmd) {
        const char *b = cmd; const char *s = strrchr(cmd, '\\');
        if (s) b = s + 1;
        is_ggnet = (gp_stricmp(b, "ggnet.exe") == 0 || gp_stricmp(b, "ggnet") == 0);
    }
    if (!is_ggnet) return p_CreateProcessA(app, cmd, sa, ta, inherit, flags, env, cwd, si, pi);

    DWORD nflags = flags | CREATE_SUSPENDED;
    BOOL r = p_CreateProcessA(app, cmd, sa, ta, inherit, nflags, env, cwd, si, pi);
    if (!r) return FALSE;

    if (g_cfg_map && pi) g_cfg_map->childPid = pi->dwProcessId;
    if (g_child_event) SetEvent(g_child_event);
    if (g_done_event) WaitForSingleObject(g_done_event, 15000);
    if (pi && pi->hThread) { ResumeThread(pi->hThread); }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* CPUID hypervisor-leaf patching (patch `mov eax,0x40000000; cpuid`)  */
/* ------------------------------------------------------------------ */
static PVOID g_veh = NULL;

static LONG CALLBACK gp_veh_handler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        unsigned char *rip = (unsigned char *)ep->ExceptionRecord->ExceptionAddress;
        /* Only treat a CC CC as ours if it follows `mov eax, 0x40000000`. */
        if (rip[0] == 0xCC && rip[1] == 0xCC &&
            rip[-5] == 0xB8 && rip[-4] == 0x00 && rip[-3] == 0x00 &&
            rip[-2] == 0x00 && rip[-1] == 0x40) {
#ifdef _WIN64
            DWORD leaf = (DWORD)ep->ContextRecord->Rax;
            if (leaf >= 0x40000000u && leaf <= 0x400000FFu) {
                ep->ContextRecord->Rax = 0;
                ep->ContextRecord->Rbx = 0;
                ep->ContextRecord->Rcx = 0;
                ep->ContextRecord->Rdx = 0;
            }
            ep->ContextRecord->Rip += 2;
#else
            DWORD leaf = ep->ContextRecord->Eax;
            if (leaf >= 0x40000000u && leaf <= 0x400000FFu) {
                ep->ContextRecord->Eax = 0;
                ep->ContextRecord->Ebx = 0;
                ep->ContextRecord->Ecx = 0;
                ep->ContextRecord->Edx = 0;
            }
            ep->ContextRecord->Eip += 2;
#endif
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void gp_patch_cpuid_range(unsigned char *base, size_t size) {
    static const unsigned char pat[] = {0xB8,0x00,0x00,0x00,0x40,0x0F,0xA2};
    size_t i;
    if (!base || size < 7) return;
    for (i = 0; i + 7 <= size; i++) {
        if (memcmp(base + i, pat, 7) == 0) {
            DWORD old = gp_unprotect(base + i + 5, 2);
            base[i + 5] = 0xCC;   /* cpuid -> int3 ; int3 */
            base[i + 6] = 0xCC;
            gp_reprotect(base + i + 5, 2, old);
        }
    }
}

static void gp_patch_module(const wchar_t *name) {
    HMODULE mod = GetModuleHandleW(name);
    if (!mod) return;
    MODULEINFO mi;
    if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) {
        gp_patch_cpuid_range((unsigned char *)mod, mi.SizeOfImage);
    }
}

static void gp_scan_cpuid(void) {
    HMODULE main = GetModuleHandleW(NULL);
    if (main) {
        MODULEINFO mi;
        if (GetModuleInformation(GetCurrentProcess(), main, &mi, sizeof(mi)))
            gp_patch_cpuid_range((unsigned char *)main, mi.SizeOfImage);
    }
    gp_patch_module(L"IronANE.dll");
    gp_patch_module(L"LockneANE.Windows.dll");
    gp_patch_module(L"CppGeoLocs.dll");
    gp_patch_module(L"Loki.dll");
    gp_patch_module(L"Loai.dll");
}

static DWORD WINAPI gp_rescan_thread(LPVOID p) {
    int i;
    for (i = 0; i < 90; i++) {
        gp_scan_cpuid();
        Sleep(1000);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Installation                                                        */
/* ------------------------------------------------------------------ */
static void gp_hook(HMODULE mod, const char *name, void *detour, void **orig, GP_HOOK *slot) {
    FARPROC p = GetProcAddress(mod, name);
    if (!p) return;
    *orig = (void *)p;
    if (gp_hook_install(slot, (void *)p, detour) == 0) {
        g_hooks[g_hook_count] = *slot;
        g_hook_count++;
    }
}

static void gp_install_all(void) {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE advapi32 = GetModuleHandleW(L"advapi32.dll");
    HMODULE ntdll    = GetModuleHandleW(L"ntdll.dll");
    HMODULE iphlpapi = GetModuleHandleW(L"iphlpapi.dll");

    if (gp_flag(GP_FLAG_HIDE_DEBUGGER)) {
        gp_hook(kernel32, "IsDebuggerPresent", d_IsDebuggerPresent, (void **)&p_IsDebuggerPresent, &g_hooks[g_hook_count]);
        gp_hook(kernel32, "CheckRemoteDebuggerPresent", d_CheckRemoteDebuggerPresent, (void **)&p_CheckRemoteDebuggerPresent, &g_hooks[g_hook_count]);
    }
    if (gp_flag(GP_FLAG_HIDE_PROCESSES)) {
        gp_hook(kernel32, "Process32FirstW", d_Process32FirstW, (void **)&p_Process32FirstW, &g_hooks[g_hook_count]);
        gp_hook(kernel32, "Process32NextW", d_Process32NextW, (void **)&p_Process32NextW, &g_hooks[g_hook_count]);
        gp_hook(kernel32, "Process32First", d_Process32First, (void **)&p_Process32First, &g_hooks[g_hook_count]);
        gp_hook(kernel32, "Process32Next", d_Process32Next, (void **)&p_Process32Next, &g_hooks[g_hook_count]);
        gp_hook(ntdll, "NtQuerySystemInformation", d_NtQuerySystemInformation, (void **)&p_NtQuerySystemInformation, &g_hooks[g_hook_count]);
    }
    if (gp_flag(GP_FLAG_SPOOF_SMBIOS)) {
        gp_hook(kernel32, "GetSystemFirmwareTable", d_GetSystemFirmwareTable, (void **)&p_GetSystemFirmwareTable, &g_hooks[g_hook_count]);
    }
    if (gp_flag(GP_FLAG_SPOOF_MAC)) {
        gp_hook(iphlpapi, "GetAdaptersInfo", d_GetAdaptersInfo, (void **)&p_GetAdaptersInfo, &g_hooks[g_hook_count]);
        gp_hook(iphlpapi, "GetAdaptersAddresses", d_GetAdaptersAddresses, (void **)&p_GetAdaptersAddresses, &g_hooks[g_hook_count]);
    }
    if (gp_flag(GP_FLAG_HIDE_REGISTRY)) {
        gp_hook(advapi32, "RegOpenKeyExW", d_RegOpenKeyExW, (void **)&p_RegOpenKeyExW, &g_hooks[g_hook_count]);
        gp_hook(advapi32, "RegQueryValueExW", d_RegQueryValueExW, (void **)&p_RegQueryValueExW, &g_hooks[g_hook_count]);
    }
    /* always hook LoadLibrary (block-Loki + child process control are cheap) */
    gp_hook(kernel32, "LoadLibraryW", d_LoadLibraryW, (void **)&p_LoadLibraryW, &g_hooks[g_hook_count]);
    gp_hook(kernel32, "LoadLibraryExW", d_LoadLibraryExW, (void **)&p_LoadLibraryExW, &g_hooks[g_hook_count]);
    gp_hook(kernel32, "LoadLibraryA", d_LoadLibraryA, (void **)&p_LoadLibraryA, &g_hooks[g_hook_count]);

    /* child process control (relevant in the 32-bit launcher) */
    gp_hook(kernel32, "CreateProcessW", d_CreateProcessW, (void **)&p_CreateProcessW, &g_hooks[g_hook_count]);
    gp_hook(kernel32, "CreateProcessA", d_CreateProcessA, (void **)&p_CreateProcessA, &g_hooks[g_hook_count]);

    if (gp_flag(GP_FLAG_SPOOF_CPUID)) {
        g_veh = AddVectoredExceptionHandler(1, gp_veh_handler);
        gp_scan_cpuid();
        HANDLE t = CreateThread(NULL, 0, gp_rescan_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }

    gp_log("[GGnetPatch] hooks installed");
}

/* ------------------------------------------------------------------ */
/* DllMain                                                             */
/* ------------------------------------------------------------------ */
static DWORD WINAPI gp_init_thread(LPVOID p) {
    gp_load_config();
    gp_install_all();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        HANDLE t = CreateThread(NULL, 0, gp_init_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
