#include <stdio.h>

int extract(unsigned int a, int offset, int len)
{
    if(offset + len > 32)
        len = 32 - offset;
    return ( (((1ULL << (32 - offset)) - 1) & ~( (1ULL << (32 - offset - len)) - 1)) & a ) >> (32 - offset - len);
}


int main()
{
    printf("%x %x %x %x\n", extract(0x12345678, 0, 0), extract(0x12345678, 8, 8),extract(0x12345678, 16, 8),extract(0x12345677, 30, 8));
    unsigned int a = 0x12345678; int offset = 0; int len = 8;
    printf("%x %x %x \n", ((1ULL << (32 - offset)) - 1), ~( (1ULL << (32 - offset - len)) - 1), (((1ULL << (32 - offset)) - 1) & ~( (1ULL << (32 - offset - len)) - 1)));
}