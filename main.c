#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stddef.h>

#include "edsign.h"

typedef int8_t   i8;
typedef uint8_t  u8;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

#define RANDOM_INPUT(name, size) u8 name[size]; p_random(name, size)
#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)


// Must be seeded with a nonzero value.
// Accessible from the outside so we can modify it
u64 random_state = 0x7eed;

// Pseudo-random 64 bit number, based on xorshift*
u64 rand64()
{
    random_state ^= random_state >> 12;
    random_state ^= random_state << 25;
    random_state ^= random_state >> 27;
    return random_state * 0x2545F4914F6CDD1D; // magic constant
}

void p_random(u8 *stream, size_t size)
{
    FOR (i, 0, size) {
        stream[i] = (u8)rand64();
    }
}

void print_vector(const u8 *buf, size_t size)
{
    FOR (i, 0, size) {
        printf("%x%x", buf[i] >> 4, buf[i] & 0x0f);
    }
    printf(":\n");
}


int main(void) {
    int status = 0;

    u8 mikepk[32];
    static const u8 mike[32] = {255, 1, 2, 3 ,4, 5 ,6 ,7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 255};
    edsign_sec_to_pub(mikepk, mike);
    print_vector(mikepk, 32);


    RANDOM_INPUT(message, 32);
    RANDOM_INPUT(sk, 32);
    u8 pk       [32]; edsign_sec_to_pub(pk, sk);
    u8 signature[64]; edsign_sign(signature, pk, sk, message, 32);
    status |= edsign_verify(signature, pk, message, 32);

    printf("%s: Renesas-c25519 demo\n", status != 0 ? "FAILED" : "OK");
    return status;
}
