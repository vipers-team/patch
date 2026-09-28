/*
 * hook.c - self-contained inline (trampoline) hook engine.
 * Instruction-length decoding lives in lde.c so it can be unit-tested.
 */
#include "ggpatch.h"
#include "lde.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/* Jump helpers                                                        */
/* ------------------------------------------------------------------ */
#ifdef _WIN64
#  define GP_OVERWRITE_LEN 14
#else
#  define GP_OVERWRITE_LEN 5
#endif

static void gp_write_abs_jump(BYTE *dst, const void *to) {
#ifdef _WIN64
    dst[0] = 0xFF; dst[1] = 0x25;            /* jmp qword ptr [rip+0] */
    *(DWORD *)(dst + 2) = 0;
    *(const void **)(dst + 6) = to;          /* absolute address */
#else
    dst[0] = 0xE9;                            /* jmp rel32 */
    *(DWORD *)(dst + 1) = (DWORD)((INT_PTR)to - ((INT_PTR)dst + 5));
#endif
}

/* ------------------------------------------------------------------ */
/* Thread suspension (best-effort atomic patching)                     */
/* ------------------------------------------------------------------ */
static void gp_suspend_threads(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD self = GetCurrentThreadId();
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == GetCurrentProcessId() && te.th32ThreadID != self) {
                HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (t) { SuspendThread(t); CloseHandle(t); }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static void gp_resume_threads(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD self = GetCurrentThreadId();
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == GetCurrentProcessId() && te.th32ThreadID != self) {
                HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (t) { ResumeThread(t); CloseHandle(t); }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

/* ------------------------------------------------------------------ */
/* Public hook API                                                     */
/* ------------------------------------------------------------------ */
int gp_hook_install(GP_HOOK *h, void *target, void *detour) {
    gp_ins ins;
    size_t need = GP_OVERWRITE_LEN;
    size_t covered = 0;
    const unsigned char *p = (const unsigned char *)target;
    int is64 = 0;
#ifdef _WIN64
    is64 = 1;
#endif

    memset(h, 0, sizeof(*h));
    h->target = target;
    h->detour = detour;

    /* decode forward until we cover the overwrite bytes, on clean boundaries */
    while (covered < need) {
        size_t n = gp_lde(p + covered, is64, &ins);
        if (n == 0) return 1; /* cannot decode: abort rather than corrupt */
        covered += n;
        if (covered > 64) return 1;
    }
    h->saved_len = covered;

    /* allocate executable trampoline */
    h->trampoline = (BYTE *)VirtualAlloc(NULL, covered + GP_OVERWRITE_LEN + 16,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!h->trampoline) return 1;

    /* copy original bytes + fix RIP-relative displacements */
    memcpy(h->saved, target, covered);
    memcpy(h->trampoline, target, covered);

    covered = 0;
    while (covered < h->saved_len) {
        size_t n = gp_lde((const unsigned char *)target + covered, is64, &ins);
        if (n == 0) { VirtualFree(h->trampoline, 0, MEM_RELEASE); return 1; }
        if (is64 && ins.rip_rel) {
            INT_PTR orig_addr = (INT_PTR)target + covered;
            INT_PTR new_addr  = (INT_PTR)h->trampoline + covered;
            DWORD  old_disp   = *(DWORD *)(h->trampoline + covered + ins.disp_off);
            INT_PTR disp = (INT_PTR)(INT32)old_disp + (orig_addr - new_addr);
            *(DWORD *)(h->trampoline + covered + ins.disp_off) = (DWORD)disp;
        }
        covered += n;
    }

    /* append jump back to target + saved_len */
    gp_write_abs_jump(h->trampoline + h->saved_len, (BYTE *)target + h->saved_len);

    /* install the detour */
    gp_suspend_threads();
    {
        DWORD old = gp_unprotect(target, GP_OVERWRITE_LEN);
        gp_write_abs_jump((BYTE *)target, detour);
        gp_reprotect(target, GP_OVERWRITE_LEN, old);
    }
    gp_resume_threads();

    FlushInstructionCache(GetCurrentProcess(), target, GP_OVERWRITE_LEN);
    FlushInstructionCache(GetCurrentProcess(), h->trampoline, h->saved_len + GP_OVERWRITE_LEN);

    h->installed = 1;
    return 0;
}

int gp_hook_remove(GP_HOOK *h) {
    if (!h || !h->installed) return 1;
    gp_suspend_threads();
    {
        DWORD old = gp_unprotect(h->target, GP_OVERWRITE_LEN);
        memcpy(h->target, h->saved, h->saved_len);
        gp_reprotect(h->target, GP_OVERWRITE_LEN, old);
    }
    gp_resume_threads();
    FlushInstructionCache(GetCurrentProcess(), h->target, GP_OVERWRITE_LEN);
    if (h->trampoline) VirtualFree(h->trampoline, 0, MEM_RELEASE);
    h->trampoline = NULL;
    h->installed = 0;
    return 0;
}

int gp_hook_enable(GP_HOOK *h) {
    if (!h || !h->installed) return 1;
    gp_suspend_threads();
    {
        DWORD old = gp_unprotect(h->target, GP_OVERWRITE_LEN);
        gp_write_abs_jump((BYTE *)h->target, h->detour);
        gp_reprotect(h->target, GP_OVERWRITE_LEN, old);
    }
    gp_resume_threads();
    FlushInstructionCache(GetCurrentProcess(), h->target, GP_OVERWRITE_LEN);
    return 0;
}

int gp_hook_disable(GP_HOOK *h) {
    if (!h || !h->installed) return 1;
    gp_suspend_threads();
    {
        DWORD old = gp_unprotect(h->target, GP_OVERWRITE_LEN);
        memcpy(h->target, h->saved, h->saved_len);
        gp_reprotect(h->target, GP_OVERWRITE_LEN, old);
    }
    gp_resume_threads();
    FlushInstructionCache(GetCurrentProcess(), h->target, GP_OVERWRITE_LEN);
    return 0;
}
