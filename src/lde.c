/*
 * lde.c - portable x86/x64 length-disassembler.
 *
 * Decodes enough of the ISA to find clean instruction boundaries for inline
 * hooking. VEX/EVEX are intentionally unsupported (they never appear in the
 * Win32 API prologues this project hooks); encountering one yields 0 so the
 * caller aborts safely instead of corrupting code.
 */
#include "lde.h"

/* Decode the ModRM/SIB/displacement portion. p points at the ModRM byte.
 * Returns bytes consumed starting at p (ModRM included). */
static size_t gp_modrm(const unsigned char *p, int is64, gp_ins *out) {
    unsigned char modrm = *p;
    int mod = modrm >> 6;
    int rm  = modrm & 7;
    size_t len = 1;

    out->rip_rel = 0; out->disp_off = 0;

    if (mod == 3) return len; /* register form */

    if (rm == 4) { /* SIB follows */
        unsigned char sib = p[len];
        len++;
        if (mod == 0 && (sib & 7) == 5) { /* no base + disp32 */
            out->disp_off = len; len += 4;
        }
    }

    if (mod == 1) {
        out->disp_off = len; len += 1;
    } else if (mod == 2) {
        out->disp_off = len; len += 4;
    } else { /* mod == 0 */
        if (is64 && rm == 5) { /* RIP-relative */
            out->rip_rel = 1; out->disp_off = len; len += 4;
        } else if (rm == 5) {  /* absolute disp32 (32-bit mode) */
            out->disp_off = len; len += 4;
        }
    }
    return len;
}

size_t gp_lde(const unsigned char *p, int is64, gp_ins *out) {
    const unsigned char *start = p;
    int opsize66 = 0;
    int rexw = 0;
    unsigned char op;

    out->len = 0; out->rip_rel = 0; out->disp_off = 0;

    /* prefix loop */
    for (;;) {
        unsigned char b = *p;
        if (b == 0x66) { opsize66 = 1; p++; continue; }
        if (b == 0x67) { p++; continue; }                 /* address-size: ignored, rare in prologues */
        if (b == 0xF0 || b == 0xF2 || b == 0xF3) { p++; continue; }
        if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { p++; continue; }
        if (is64 && (b & 0xF0) == 0x40) { rexw = (b >> 3) & 1; p++; continue; }
        break;
    }

    op = *p++;

    /* VEX/EVEX are not expected in the prologues we hook. Bail cleanly. */
    if (is64 && (op == 0xC4 || op == 0xC5 || op == 0x62)) return 0;

    /* ---- two-byte map ---- */
    if (op == 0x0F) {
        unsigned char op2 = *p++;
        size_t modrm_len = 0;
        int has_modrm = 0;
        int imm = 0;

        /* 0F 38 / 0F 3A three-byte map: all have ModRM, 3A has imm8 */
        if (op2 == 0x38 || op2 == 0x3A) {
            p++; /* consume the real opcode byte */
            modrm_len = gp_modrm(p, is64, out);
            p += modrm_len;
            if (op2 == 0x3A) { p += 1; }
            out->len = (size_t)(p - start);
            return out->len;
        }

        switch (op2) {
            case 0x1F: has_modrm = 1; break;                     /* NOP r/m */
            case 0x31: break;                                     /* RDTSC */
            case 0xA2: break;                                     /* CPUID */
            case 0x05: case 0x0B: break;                          /* SYSCALL / UD2 */
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44:
            case 0x45: case 0x46: case 0x47: case 0x48: case 0x49:
            case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                has_modrm = 1; break;                             /* CMOVcc */
            case 0x80: case 0x81: case 0x82: case 0x83: case 0x84:
            case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
            case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
                imm = 4; break;                                   /* Jcc rel32 */
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94:
            case 0x95: case 0x96: case 0x97: case 0x98: case 0x99:
            case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
                has_modrm = 1; break;                             /* SETcc r/m8 */
            case 0xA3: has_modrm = 1; break;                      /* BT */
            case 0xA4: case 0xAC:
                has_modrm = 1; imm = 1; break;                    /* SHLD/SHRD imm8 */
            case 0xA5: case 0xAD:
                has_modrm = 1; break;                             /* SHLD/SHRD CL */
            case 0xAB: has_modrm = 1; break;                      /* BTS */
            case 0xAF: has_modrm = 1; break;                      /* IMUL */
            case 0xB3: has_modrm = 1; break;                      /* BTR */
            case 0xB6: case 0xB7: has_modrm = 1; break;           /* MOVZX */
            case 0xBA: has_modrm = 1; imm = 1; break;             /* BT/BTS/BTR/BTC, imm8 */
            case 0xBB: has_modrm = 1; break;                      /* BTC */
            case 0xBC: case 0xBD: has_modrm = 1; break;           /* BSF/BSR */
            case 0xBE: case 0xBF: has_modrm = 1; break;           /* MOVSX */
            case 0xC0: case 0xC1: has_modrm = 1; break;           /* XADD */
            case 0xC2: case 0xC4: case 0xC5: case 0xC6:
                has_modrm = 1; imm = 1; break;                    /* CMPSS/CMPPS etc imm8 */
            case 0xC3: has_modrm = 1; break;                      /* MOVNTI */
            case 0xC7: has_modrm = 1; break;                      /* CMPXCHG8B/16B (group) */
            case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15:
            case 0x16: case 0x17: case 0x18: case 0x19: case 0x1A: case 0x1B:
            case 0x1C: case 0x1D: case 0x1E:
            case 0x28: case 0x29: case 0x2A: case 0x2B: case 0x2C: case 0x2D:
            case 0x2E: case 0x2F:
            case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
            case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65:
            case 0x66: case 0x67: case 0x68: case 0x69: case 0x6A: case 0x6B:
            case 0x6C: case 0x6D: case 0x6E: case 0x6F:
            case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            case 0xD0: case 0xD1: case 0xD2: case 0xD3: case 0xD4: case 0xD5:
            case 0xD6: case 0xD7: case 0xD8: case 0xD9: case 0xDA: case 0xDB:
            case 0xDC: case 0xDD: case 0xDE: case 0xDF:
            case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5:
            case 0xE6: case 0xE7: case 0xE8: case 0xE9: case 0xEA: case 0xEB:
            case 0xEC: case 0xED: case 0xEE: case 0xEF:
            case 0xF0: case 0xF1: case 0xF2: case 0xF3: case 0xF4: case 0xF5:
            case 0xF6: case 0xF7: case 0xF8: case 0xF9: case 0xFA: case 0xFB:
            case 0xFC: case 0xFD: case 0xFE: case 0xFF:
                has_modrm = 1; break;                             /* SSE/SSE2 scalar/vector */
            case 0x70: case 0x71: case 0x72: case 0x73:
                has_modrm = 1; imm = 1; break;                    /* PSLL/PSRL/PSRA imm8 */
            default:
                return 0; /* undecodable */
        }

        if (has_modrm) {
            gp_ins mo; mo.rip_rel = 0; mo.disp_off = 0; mo.len = 0;
            modrm_len = gp_modrm(p, is64, &mo);
            out->rip_rel = mo.rip_rel;
            out->disp_off = mo.disp_off;
            p += modrm_len;
        }
        p += imm;
        out->len = (size_t)(p - start);
        return out->len;
    }

    /* ---- one-byte map ---- */
    {
        size_t modrm_len = 0;
        int has_modrm = 0;
        int imm = 0;
        int imm_opsize = 0;  /* 1 -> imm is 2 bytes with 0x66, else 4 */
        int imm_rexw = 0;    /* 1 -> imm is 8 bytes with REX.W, else 4 */

        if (op >= 0x50 && op <= 0x57) { out->len = (size_t)(p - start); return out->len; } /* PUSH r */
        if (op >= 0x58 && op <= 0x5F) { out->len = (size_t)(p - start); return out->len; } /* POP r */
        if (!is64 && op >= 0x40 && op <= 0x47) { out->len = (size_t)(p - start); return out->len; } /* INC r */
        if (!is64 && op >= 0x48 && op <= 0x4F) { out->len = (size_t)(p - start); return out->len; } /* DEC r */
        if (op >= 0x70 && op <= 0x7F) { p += 1; out->len = (size_t)(p - start); return out->len; } /* Jcc rel8 */
        if (op >= 0x90 && op <= 0x97) { out->len = (size_t)(p - start); return out->len; } /* NOP / XCHG */
        if (op >= 0xB0 && op <= 0xB7) { p += 1; out->len = (size_t)(p - start); return out->len; } /* MOV r8,imm8 */
        if (op >= 0xB8 && op <= 0xBF) { out->len = (size_t)(p - start) + (rexw ? 8 : (opsize66 ? 2 : 4)); return out->len; } /* MOV r,imm */

        switch (op) {
            case 0x00: case 0x01: case 0x02: case 0x03:
            case 0x08: case 0x09: case 0x0A: case 0x0B:
            case 0x10: case 0x11: case 0x12: case 0x13:
            case 0x18: case 0x19: case 0x1A: case 0x1B:
            case 0x20: case 0x21: case 0x22: case 0x23:
            case 0x28: case 0x29: case 0x2A: case 0x2B:
            case 0x30: case 0x31: case 0x32: case 0x33:
            case 0x38: case 0x39: case 0x3A: case 0x3B:
                has_modrm = 1; break;
            case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C: case 0x34: case 0x3C:
                imm = 1; break;                                   /* AL,imm8 */
            case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D: case 0x35: case 0x3D:
                imm_opsize = 1; imm = 4; break;                   /* eAX,imm */
            case 0x06: case 0x07: case 0x0E: case 0x16: case 0x17: case 0x1E: case 0x1F:
                break;
            case 0x27: case 0x2F: case 0x37: case 0x3F: break;

            case 0x63: has_modrm = 1; break;                      /* MOVSXD/ARPL */
            case 0x68: imm = 4; imm_opsize = 1; break;            /* PUSH imm */
            case 0x69: has_modrm = 1; imm = 4; imm_opsize = 1; break; /* IMUL r,r/m,imm */
            case 0x6A: imm = 1; break;                            /* PUSH imm8 */
            case 0x6B: has_modrm = 1; imm = 1; break;             /* IMUL r,r/m,imm8 */
            case 0x6C: case 0x6D: case 0x6E: case 0x6F: break;
            case 0x80: has_modrm = 1; imm = 1; break;
            case 0x81: has_modrm = 1; imm = 4; imm_opsize = 1; break;
            case 0x82: has_modrm = 1; imm = 1; break;
            case 0x83: has_modrm = 1; imm = 1; break;
            case 0x84: case 0x85: case 0x86: case 0x87: has_modrm = 1; break;
            case 0x88: case 0x89: case 0x8A: case 0x8B: has_modrm = 1; break;
            case 0x8C: case 0x8E: has_modrm = 1; break;
            case 0x8D: has_modrm = 1; break;                      /* LEA */
            case 0x8F: has_modrm = 1; break;
            case 0x98: case 0x99: break;
            case 0x9A: p += 6; out->len = (size_t)(p - start); return out->len;
            case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F: break;
            case 0xA0: case 0xA1: case 0xA2: case 0xA3:
                p += 4 + (is64 ? 4 : 0); out->len = (size_t)(p - start); return out->len;
            case 0xA4: case 0xA5: case 0xA6: case 0xA7: case 0xAA: case 0xAB:
            case 0xAC: case 0xAD: case 0xAE: case 0xAF: break;
            case 0xA8: imm = 1; break;
            case 0xA9: imm = 4; imm_opsize = 1; break;
            case 0xC0: case 0xC1: has_modrm = 1; imm = 1; break;
            case 0xC2: case 0xCA: imm = 2; break;
            case 0xC3: case 0xCB: break;
            case 0xC6: has_modrm = 1; imm = 1; break;
            case 0xC7: has_modrm = 1; imm = 4; imm_opsize = 1; break;
            case 0xC8: imm = 3; break;
            case 0xC9: break;
            case 0xCC: case 0xCE: case 0xCF: case 0xF1: case 0xF4:
            case 0xF5: case 0xF8: case 0xF9: case 0xFA: case 0xFB:
            case 0xFC: case 0xFD: break;
            case 0xCD: imm = 1; break;
            case 0xD0: case 0xD1: case 0xD2: case 0xD3: has_modrm = 1; break;
            case 0xD4: case 0xD5: imm = 1; break;
            case 0xD6: case 0xD7: break;
            case 0xD8: case 0xD9: case 0xDA: case 0xDB:
            case 0xDC: case 0xDD: case 0xDE: case 0xDF: has_modrm = 1; break;
            case 0xE0: case 0xE1: case 0xE2: case 0xE3: imm = 1; break;
            case 0xE4: case 0xE5: case 0xE6: case 0xE7: imm = 1; break;
            case 0xE8: case 0xE9: imm = 4; imm_opsize = 1; break;
            case 0xEA: p += 6; out->len = (size_t)(p - start); return out->len;
            case 0xEB: imm = 1; break;
            case 0xEC: case 0xED: case 0xEE: case 0xEF: break;
            case 0xF6: has_modrm = 1; imm = 1; break;
            case 0xF7: has_modrm = 1; imm = 4; imm_opsize = 1; break;
            case 0xFE: has_modrm = 1; break;
            case 0xFF: has_modrm = 1; break;
            case 0x62: has_modrm = 1; break;                      /* BOUND (32-bit) */
            case 0xC4: case 0xC5: has_modrm = 1; break;           /* LES/LDS (32-bit) */
            default:
                return 0;
        }

        if (has_modrm) {
            gp_ins mo; mo.rip_rel = 0; mo.disp_off = 0; mo.len = 0;
            modrm_len = gp_modrm(p, is64, &mo);
            out->rip_rel = mo.rip_rel;
            out->disp_off = mo.disp_off;
            p += modrm_len;
        }
        if (imm) {
            size_t n = imm;
            if (imm_opsize) n = opsize66 ? 2 : 4;
            if (imm_rexw) n = rexw ? 8 : (opsize66 ? 2 : 4);
            p += n;
        }
        out->len = (size_t)(p - start);
        return out->len;
    }
}
