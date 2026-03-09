#pragma once

#include <stddef.h>

#include "../../lib/parity/parity.h"
#include <lib/nfc/protocols/mf_classic/mf_classic.h>

typedef struct {
    uint32_t odd;
    uint32_t even;
} NestedCrypto1;

#define LF_POLY_ODD (0x29CE5C)
#define LF_POLY_EVEN (0x870804)

#define SWAPENDIAN(x) \
    ((x) = ((x) >> 8 & 0xff00ff) | ((x)&0xff00ff) << 8, (x) = (x) >> 16 | (x) << 16)
#define BEBIT(x, n) FURI_BIT(x, (n) ^ 24)

void nested_crypto1_reset(NestedCrypto1* crypto1);

void nested_crypto1_init(NestedCrypto1* crypto1, uint64_t key);

uint32_t nested_crypto1_filter(uint32_t in);

uint8_t nested_crypto1_bit(NestedCrypto1* crypto1, uint8_t in, int is_encrypted);

uint8_t nested_crypto1_byte(NestedCrypto1* crypto1, uint8_t in, int is_encrypted);

uint32_t nested_crypto1_word(NestedCrypto1* crypto1, uint32_t in, int is_encrypted);

uint32_t nested_prng_successor(uint32_t x, uint32_t n);

void nested_crypto1_decrypt(
    NestedCrypto1* crypto,
    uint8_t* encrypted_data,
    uint16_t encrypted_data_bits,
    uint8_t* decrypted_data);

void nested_crypto1_encrypt(
    NestedCrypto1* crypto,
    uint8_t* keystream,
    uint8_t* plain_data,
    uint16_t plain_data_bits,
    uint8_t* encrypted_data,
    uint8_t* encrypted_parity);
