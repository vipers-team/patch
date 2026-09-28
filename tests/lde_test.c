/*
 * lde_test.c - unit test for the portable length-disassembler.
 * Compiles and runs on macOS/Linux (no Windows dependency).
 */
#include <stdio.h>
#include <string.h>
#include "lde.h"

static int failures = 0;

static void expect(const unsigned char *bytes, size_t nbytes, int is64,
                   size_t want_len, int want_rip) {
    gp_ins ins;
    size_t got = gp_lde(bytes, is64, &ins);
    int ok = (got == want_len) && (ins.rip_rel == want_rip);
    if (!ok) {
        failures++;
        printf("FAIL is64=%d bytes=", is64);
        for (size_t i = 0; i < nbytes; i++) printf("%02X ", bytes[i]);
        printf("-> len=%zu (want %zu), rip_rel=%d (want %d)\n",
               got, want_len, ins.rip_rel, want_rip);
    }
}

int main(void) {
    /* ---------- 64-bit ---------- */
    {
        unsigned char b1[] = {0x48,0x89,0x5C,0x24,0x08};            /* mov [rsp+8], rbx */
        expect(b1, 5, 1, 5, 0);
        unsigned char b2[] = {0x48,0x83,0xEC,0x28};                 /* sub rsp, 0x28 */
        expect(b2, 4, 1, 4, 0);
        unsigned char b3[] = {0x48,0x8B,0x05,0x01,0x02,0x03,0x04};  /* mov rax,[rip+disp32] */
        expect(b3, 7, 1, 7, 1);
        unsigned char b4[] = {0xE8,0x11,0x22,0x33,0x44};            /* call rel32 */
        expect(b4, 5, 1, 5, 0);
        unsigned char b5[] = {0x0F,0xA2};                           /* cpuid */
        expect(b5, 2, 1, 2, 0);
        unsigned char b6[] = {0xB8,0x00,0x00,0x00,0x40};            /* mov eax, 0x40000000 */
        expect(b6, 5, 1, 5, 0);
        unsigned char b7[] = {0x0F,0x1F,0x44,0x00,0x00};            /* nop [rax+rax] */
        expect(b7, 5, 1, 5, 0);
        unsigned char b8[] = {0xC3};                                /* ret */
        expect(b8, 1, 1, 1, 0);
        unsigned char b9[] = {0x48,0x8D,0x0D,0xAA,0xBB,0xCC,0xDD};  /* lea rcx,[rip+disp32] */
        expect(b9, 7, 1, 7, 1);
        unsigned char b10[] = {0x66,0x0F,0x1F,0x84,0x00,0,0,0,0};   /* nop word [rax+rax+0] */
        expect(b10, 9, 1, 9, 0);
        unsigned char b11[] = {0x4C,0x8B,0x05,0x00,0x00,0x00,0x00}; /* mov r8,[rip+disp32] */
        expect(b11, 7, 1, 7, 1);
        unsigned char b12[] = {0x48,0xB8,0,0,0,0,0,0,0,0};          /* mov rax, imm64 */
        expect(b12, 10, 1, 10, 0);
        unsigned char b13[] = {0x48,0x83,0xC4,0x28};                /* add rsp, 0x28 */
        expect(b13, 4, 1, 4, 0);
        unsigned char b14[] = {0x48,0x8B,0x4C,0x24,0x30};           /* mov rcx,[rsp+0x30] */
        expect(b14, 5, 1, 5, 0);
        unsigned char b15[] = {0xCC};                               /* int3 */
        expect(b15, 1, 1, 1, 0);
        unsigned char b16[] = {0x41,0x54};                          /* push r12 */
        expect(b16, 2, 1, 2, 0);
    }

    /* ---------- 32-bit ---------- */
    {
        unsigned char b1[] = {0x8B,0xFF};                           /* mov edi,edi */
        expect(b1, 2, 0, 2, 0);
        unsigned char b2[] = {0x55};                                /* push ebp */
        expect(b2, 1, 0, 1, 0);
        unsigned char b3[] = {0x8B,0xEC};                           /* mov ebp,esp */
        expect(b3, 2, 0, 2, 0);
        unsigned char b4[] = {0xE9,0x11,0x22,0x33,0x44};            /* jmp rel32 */
        expect(b4, 5, 0, 5, 0);
        unsigned char b5[] = {0x68,0x11,0x22,0x33,0x44};            /* push imm32 */
        expect(b5, 5, 0, 5, 0);
        unsigned char b6[] = {0x6A,0x01};                           /* push imm8 */
        expect(b6, 2, 0, 2, 0);
        unsigned char b7[] = {0xB8,0x00,0x00,0x00,0x40};            /* mov eax, 0x40000000 */
        expect(b7, 5, 0, 5, 0);
        unsigned char b8[] = {0x0F,0xA2};                           /* cpuid */
        expect(b8, 2, 0, 2, 0);
        unsigned char b9[] = {0xC3};                                /* ret */
        expect(b9, 1, 0, 1, 0);
        unsigned char b10[] = {0xFF,0x15,0xAA,0xBB,0xCC,0xDD};      /* call [disp32] */
        expect(b10, 6, 0, 6, 0);
        unsigned char b11[] = {0x8B,0x45,0x08};                     /* mov eax,[ebp+8] */
        expect(b11, 3, 0, 3, 0);
        unsigned char b12[] = {0x83,0xEC,0x10};                     /* sub esp, 0x10 */
        expect(b12, 3, 0, 3, 0);
        unsigned char b13[] = {0x81,0xEC,0x00,0x01,0x00,0x00};      /* sub esp, 0x100 */
        expect(b13, 6, 0, 6, 0);
    }

    if (failures == 0) {
        printf("ALL LDE TESTS PASSED\n");
        return 0;
    }
    printf("%d LDE TEST(S) FAILED\n", failures);
    return 1;
}
