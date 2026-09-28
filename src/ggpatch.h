/*
 * GGnetPatch - shared header
 *
 * A self-contained runtime spoofer for the GGnet (NSUS "Iron" / GGPoker)
 * AIR poker client. It runs inside the target process and fakes the
 * OS-level values the client uses to detect virtual machines.
 *
 * Build: see Makefile. Two hook DLLs are produced from the same sources:
 *   - gghook32.dll  -> injected into launcher.exe (32-bit)
 *   - gghook64.dll  -> injected into GGnet.exe  (64-bit AIR runtime)
 *
 * This file is intentionally dependency-free (Windows SDK only) so it can
 * be cross-compiled with mingw-w64.
 */
#ifndef GGPATCH_H
#define GGPATCH_H

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>   /* must precede windows.h so IP_ADAPTER_ADDRESSES is defined */
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winreg.h>
#include <iphlpapi.h>
#include <setupapi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Shared names (Local\ namespace: no admin / SeCreateGlobalPrivilege)  */
/* ------------------------------------------------------------------ */
#define GP_MAP_NAME        L"Local\\GGPatch_ConfigMap"
#define GP_CHILD_EVENT     L"Local\\GGPatch_ChildReady"
#define GP_DONE_EVENT      L"Local\\GGPatch_InjectDone"

/* ------------------------------------------------------------------ */
/* Feature flags                                                       */
/* ------------------------------------------------------------------ */
#define GP_FLAG_HIDE_PROCESSES  0x00000001u   /* filter Toolhelp + NtQuerySystemInformation */
#define GP_FLAG_SPOOF_CPUID     0x00000002u   /* patch CPUID hypervisor leaf (0x40000000) */
#define GP_FLAG_HIDE_DEBUGGER   0x00000004u   /* IsDebuggerPresent / CheckRemoteDebuggerPresent */
#define GP_FLAG_SPOOF_SMBIOS    0x00000008u   /* GetSystemFirmwareTable */
#define GP_FLAG_SPOOF_MAC       0x00000010u   /* GetAdaptersInfo / GetAdaptersAddresses */
#define GP_FLAG_HIDE_REGISTRY   0x00000020u   /* RegOpenKeyExW / RegQueryValueExW */
#define GP_FLAG_BLOCK_LOKI      0x00000040u   /* block Loki.dll / Loai.dll load */
#define GP_FLAG_ALL             0xFFFFFFFFu

typedef struct _GP_CONFIG {
    DWORD flags;
    DWORD blockLoki;              /* nonzero -> reject Loki/Loai LoadLibrary */
    DWORD childPid;               /* set by the hook DLL when it suspends GGnet.exe */
    DWORD reserved[29];
} GP_CONFIG;

/* ------------------------------------------------------------------ */
/* String helpers (header-only, no CRT dependency surprises)           */
/* ------------------------------------------------------------------ */
static __inline int gp_tolower(int c) { return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c; }

static __inline int gp_stricmp(const char *a, const char *b) {
    while (*a && *b) {
        int ca = gp_tolower((unsigned char)*a), cb = gp_tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return gp_tolower((unsigned char)*a) - gp_tolower((unsigned char)*b);
}

static __inline int gp_wcsicmp(const wchar_t *a, const wchar_t *b) {
    while (*a && *b) {
        wchar_t ca = (wchar_t)gp_tolower((unsigned short)*a);
        wchar_t cb = (wchar_t)gp_tolower((unsigned short)*b);
        if (ca != cb) return (int)(ca - cb);
        a++; b++;
    }
    return (int)((wchar_t)gp_tolower((unsigned short)*a) - (wchar_t)gp_tolower((unsigned short)*b));
}

/* case-insensitive substring search (ANSI) */
static __inline const char *gp_stristr(const char *hay, const char *needle) {
    if (!*needle) return hay;
    for (; *hay; hay++) {
        const char *h = hay, *n = needle;
        while (*h && *n && gp_tolower((unsigned char)*h) == gp_tolower((unsigned char)*n)) { h++; n++; }
        if (!*n) return hay;
    }
    return NULL;
}

/* case-insensitive substring search (wide) */
static __inline const wchar_t *gp_wcsistr(const wchar_t *hay, const wchar_t *needle) {
    if (!*needle) return hay;
    for (; *hay; hay++) {
        const wchar_t *h = hay, *n = needle;
        while (*h && *n && gp_tolower((unsigned short)*h) == gp_tolower((unsigned short)*n)) { h++; n++; }
        if (!*n) return hay;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* VM detection tables                                                 */
/* ------------------------------------------------------------------ */
static __inline int gp_process_name_is_vm(const wchar_t *name) {
    static const wchar_t *const names[] = {
        L"vmware", L"vmtoolsd", L"vmwaretray", L"vmwareuser", L"vmacthlp",
        L"vm3dservice", L"vmsrvc", L"vgauth", L"vmtools",
        L"virtualbox", L"vboxservice", L"vboxtray", L"vboxclient", L"vbox",
        L"qemu", L"qemu-ga",
        L"prl_", L"prltools", L"parallels",
        L"xenservice", L"xenbus",
        L"vmusrvc", L"vmware-vmx"
    };
    size_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (gp_wcsistr(name, names[i])) return 1;
    }
    return 0;
}

/* Returns nonzero when the first 3 bytes of mac are a known VM OUI. */
static __inline int gp_mac_is_vm(const unsigned char mac[6]) {
    static const unsigned char ouis[][3] = {
        {0x00,0x0C,0x29}, {0x00,0x50,0x56}, {0x00,0x05,0x69}, {0x00,0x1C,0x14}, /* VMware */
        {0x08,0x00,0x27}, {0x0A,0x00,0x27},                                        /* VirtualBox */
        {0x52,0x54,0x00}, {0x52,0x54,0x01},                                        /* QEMU/KVM */
        {0x00,0x16,0x3E},                                                          /* Xen */
        {0x00,0x15,0x5D},                                                          /* Hyper-V */
        {0x00,0x1C,0x42}, {0x00,0x1C,0x63}                                         /* Parallels */
    };
    size_t i;
    for (i = 0; i < sizeof(ouis) / sizeof(ouis[0]); i++) {
        if (mac[0] == ouis[i][0] && mac[1] == ouis[i][1] && mac[2] == ouis[i][2]) return 1;
    }
    return 0;
}

/* Replace a VM MAC OUI with a plausible real (Intel) OUI. */
static __inline void gp_rewrite_mac(unsigned char mac[6]) {
    mac[0] = 0x00; mac[1] = 0x1B; mac[2] = 0x21; /* Intel NIC */
}

/* SMBIOS / registry vendor substrings that identify a hypervisor. */
static __inline int gp_text_is_vm(const char *s) {
    static const char *const tokens[] = {
        "vmware", "innotek", "qemu", "kvm", "xen", "bhyve", "bochs",
        "parallels", "acrn", "ovmf", "seabios", "microsoft corporation",
        "amazon ec2", "google compute", "digitalocean", "alibaba cloud"
    };
    size_t i;
    if (!s) return 0;
    for (i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
        if (gp_stristr(s, tokens[i])) return 1;
    }
    return 0;
}

/* Wide-string variant of gp_text_is_vm. */
static __inline int gp_wtext_is_vm(const wchar_t *s) {
    static const wchar_t *const tokens[] = {
        L"vmware", L"innotek", L"qemu", L"kvm", L"xen", L"bhyve", L"bochs",
        L"parallels", L"acrn", L"ovmf", L"seabios", L"microsoft corporation",
        L"amazon ec2", L"google compute", L"digitalocean", L"alibaba cloud"
    };
    size_t i;
    if (!s) return 0;
    for (i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
        if (gp_wcsistr(s, tokens[i])) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Hook engine (implemented in hook.c)                                 */
/* ------------------------------------------------------------------ */
typedef struct _GP_HOOK {
    void       *target;
    void       *detour;
    BYTE       *trampoline;   /* allocated executable copy */
    BYTE        saved[32];
    size_t      saved_len;
    int         installed;
} GP_HOOK;

/* Install an inline detour. Returns 0 on success, nonzero on failure. */
int gp_hook_install(GP_HOOK *h, void *target, void *detour);
/* Restore the original bytes. Returns 0 on success. */
int gp_hook_remove(GP_HOOK *h);
/* Apply the detour to an already-installed hook (thread-safe toggle). */
int gp_hook_enable(GP_HOOK *h);
int gp_hook_disable(GP_HOOK *h);

/* ------------------------------------------------------------------ */
/* Small cross-architecture helpers                                    */
/* ------------------------------------------------------------------ */
/* Write a dword/pointer and return old protection. Caller must restore. */
static __inline DWORD gp_unprotect(void *addr, size_t len) {
    DWORD old = 0;
    VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old);
    return old;
}
static __inline void gp_reprotect(void *addr, size_t len, DWORD old) {
    DWORD dummy = 0;
    VirtualProtect(addr, len, old, &dummy);
}

#ifdef __cplusplus
}
#endif

#endif /* GGPATCH_H */
