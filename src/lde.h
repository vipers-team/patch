/*
 * lde.h - portable x86/x64 length-disassembler. No OS dependencies, so it
 * can be unit-tested on any host (macOS/Linux/Windows).
 */
#ifndef GP_LDE_H
#define GP_LDE_H

#include <stddef.h>

typedef struct {
    size_t len;       /* instruction length in bytes, 0 if undecodable */
    int    rip_rel;   /* instruction uses RIP-relative displacement */
    size_t disp_off;  /* offset of the displacement within the instruction */
} gp_ins;

/* Decode one instruction at p. Returns its length, or 0 if undecodable.
 * is64 selects 64-bit (REX / RIP-relative) decoding. */
size_t gp_lde(const unsigned char *p, int is64, gp_ins *out);

#endif /* GP_LDE_H */
