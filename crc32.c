#include <stdio.h>
#include "crc32.h"

static sint bcrc32initialized = 0;
static u32 crc32_table[256];

static u8 crc32_reverseBit(u8 data)
{
    return ((u8) ((data << 7) & 0x80) | ((data << 5) & 0x40) |
            ((data << 3) & 0x20) | ((data << 1) & 0x10) | ((data >> 1) & 0x08) |
            ((data >> 3) & 0x04) | ((data >> 5) & 0x02) | ((data >> 7) & 0x01));
}

static void crc32_init(void)
{
    if (bcrc32initialized != 1) {
        sint i, j;
        u32 c;
        u8 *p = (u8 *) & c, *p1;
        u8 k;

        c = 0x12340000;

        for (i = 0; i < 256; ++i) {
            k = crc32_reverseBit((u8) i);
            for (c = ((u32) k) << 24, j = 8; j > 0; --j) {
                c = c & 0x80000000 ? (c << 1) ^ CRC32_POLY : (c << 1);
            }
            p1 = (u8 *) & crc32_table[i];

            p1[0] = crc32_reverseBit(p[3]);
            p1[1] = crc32_reverseBit(p[2]);
            p1[2] = crc32_reverseBit(p[1]);
            p1[3] = crc32_reverseBit(p[0]);
        }

        bcrc32initialized = 1;
    }
}

u32 getcrc32(const u8 * buf, sint len)
{
    const u8 *p;
    u32 crc;

    if (bcrc32initialized == 0)
        crc32_init();

    crc = 0xffffffff;           /* preload shift register, per CRC-32 spec */

    for (p = buf; len > 0; ++p, --len) {
        crc = crc32_table[(crc ^ *p) & 0xff] ^ (crc >> 8);
    }

    return ~crc;                /* transmit complement, per CRC-32 spec */
}
