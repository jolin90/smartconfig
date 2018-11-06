#ifndef _CRC32_H_
#define _CRC32_H_

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

typedef unsigned int uint;
typedef signed int sint;

#define CRC32_POLY 0x04c11db7

u32 getcrc32(const u8 * buf, sint len);

#endif
