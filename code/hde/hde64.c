#include "hde64.h"
#include "table64.h"

#pragma warning(push)
#pragma warning(disable:4706)

unsigned int hde64_disasm(const void *code, hde64s *hs)
{
    uint8_t x, c = 0, *p = (uint8_t *)code, cflags, opcode, pref = 0;
    uint8_t *ht = hde64_table, m_mod, m_reg, m_rm, disp_size = 0;
    uint8_t op64 = 0;

    __stosb((unsigned char*)hs, 0, sizeof(hde64s));

    for (x = 16; x; x--)
        switch (c = *p++) {
            case 0xf3: hs->p_rep = c; pref |= 0x04; break;
            case 0xf2: hs->p_rep = c; pref |= 0x02; break;
            case 0xf0: hs->p_lock = c; pref |= 0x20; break;
            case 0x26: case 0x2e: case 0x36: case 0x3e:
            case 0x64: case 0x65: hs->p_seg = c; pref |= 0x40; break;
            case 0x66: hs->p_66 = c; pref |= 0x08; break;
            case 0x67: hs->p_67 = c; pref |= 0x10; break;
            default: goto pref_done;
        }
  pref_done:

    hs->flags = (uint32_t)pref << 23;
    if (!pref) pref |= 0x01;

    if ((c & 0xf0) == 0x40) {
        hs->flags |= F_PREFIX_REX;
        hs->rex_w = (c & 0xf) >> 3;
        if (hs->rex_w && (*p & 0xf8) == 0xb8) op64++;
        hs->rex_r = (c & 7) >> 2;
        hs->rex_x = (c & 3) >> 1;
        hs->rex_b = c & 1;
        if (((c = *p++) & 0xf0) == 0x40) {
            opcode = c;
            goto error_opcode;
        }
    }

    if ((hs->opcode = c) == 0x0f) {
        hs->opcode2 = c = *p++;
        ht += 0x4a;
    } else if (c >= 0xa0 && c <= 0xa3) {
        op64++;
        if (pref & 0x10) pref |= 0x08;
        else pref &= ~0x08;
    }

    opcode = c;
    cflags = ht[ht[opcode / 4] + (opcode % 4)];

    if (cflags == 0xff) {
      error_opcode:
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
        cflags = 0;
        if ((opcode & -3) == 0x24) cflags++;
    }

    x = 0;
    if (cflags & 0x80) {
        uint16_t t = *(uint16_t *)(ht + (cflags & 0x7f));
        cflags = (uint8_t)t;
        x = (uint8_t)(t >> 8);
    }

    if (cflags & 0x01) {
        hs->flags |= F_MODRM;
        hs->modrm = c = *p++;
        hs->modrm_mod = m_mod = c >> 6;
        hs->modrm_rm = m_rm = c & 7;
        hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

        if (x && ((x << m_reg) & 0x80))
            hs->flags |= F_ERROR | F_ERROR_OPCODE;

        if (m_mod == 3) {
        } else {
            switch (m_mod) {
                case 0:
                    if (pref & 0x10) {
                        if (m_rm == 6) disp_size = 2;
                    } else if (m_rm == 5) disp_size = 4;
                    break;
                case 1: disp_size = 1; break;
                case 2: disp_size = 2; if (!(pref & 0x10)) disp_size <<= 1; break;
            }
        }

        if (m_mod != 3 && m_rm == 4) {
            hs->flags |= F_SIB;
            p++;
            hs->sib = c;
            hs->sib_scale = c >> 6;
            hs->sib_index = (c & 0x3f) >> 3;
            hs->sib_base = c & 7;
            if (hs->sib_base == 5 && !(m_mod & 1)) disp_size = 4;
        }

        p--;
        switch (disp_size) {
            case 1: hs->flags |= F_DISP8; hs->disp.disp8 = *p; break;
            case 2: hs->flags |= F_DISP16; hs->disp.disp16 = *(uint16_t *)p; break;
            case 4: hs->flags |= F_DISP32; hs->disp.disp32 = *(uint32_t *)p; break;
        }
        p += disp_size;
    }

    if (cflags & 0x10) {
        if (op64) {
            hs->flags |= F_IMM64;
            hs->imm.imm64 = *(uint64_t *)p;
            p += 8;
        } else if (!(pref & 0x08)) {
            hs->flags |= F_IMM32;
            hs->imm.imm32 = *(uint32_t *)p;
            p += 4;
        } else {
            hs->flags |= F_IMM16;
            hs->imm.imm16 = *(uint16_t *)p;
            p += 2;
        }
    }

    if (cflags & 0x02) {
        hs->flags |= F_IMM8;
        hs->imm.imm8 = *p++;
    }

    if (cflags & 0x40) {
        hs->flags |= F_IMM32 | F_RELATIVE;
        hs->imm.imm32 = *(uint32_t *)p;
        p += 4;
    } else if (cflags & 0x20) {
        hs->flags |= F_IMM8 | F_RELATIVE;
        hs->imm.imm8 = *p++;
    }

    hs->len = (uint8_t)(p-(uint8_t *)code);
    if (hs->len > 15) {
        hs->flags |= F_ERROR | F_ERROR_LENGTH;
        hs->len = 15;
    }

    return (unsigned int)hs->len;
}

#pragma warning(pop)