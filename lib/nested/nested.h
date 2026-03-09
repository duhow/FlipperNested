#pragma once

#include <furi_hal_nfc.h>
#include <lib/nfc/protocols/mf_classic/mf_classic.h>
#include "../crypto1/crypto1.h"

#include <stddef.h>
#include <storage/storage.h>
#include <stream/stream.h>
#include <stream/buffered_file_stream.h>

typedef enum {
    FuriHalNfcTxRxTypeRaw,
    FuriHalNfcTxRxTypeRxNoCrc,
} FuriHalNfcTxRxType;

typedef struct {
    uint8_t tx_data[256];
    uint8_t rx_data[256];
    uint8_t tx_parity[32];
    uint8_t rx_parity[32];
    size_t tx_bits;
    size_t rx_bits;
    FuriHalNfcTxRxType tx_rx_type;
} FuriHalNfcTxRxContext;

typedef struct {
    uint8_t uid[10];
    uint8_t uid_len;
    uint8_t atqa[2];
    uint8_t sak;
    uint32_t cuid;
} FuriHalNfcDevData;

bool furi_hal_nfc_activate_nfca(uint32_t timeout_ms, uint32_t* cuid);

static inline uint64_t bytes2num(const uint8_t* bytes, size_t len) {
    uint64_t num = 0;
    for(size_t i = 0; i < len; i++) {
        num = (num << 8) | bytes[i];
    }
    return num;
}

static inline void num2bytes(uint64_t num, size_t len, uint8_t* bytes) {
    for(size_t i = 0; i < len; i++) {
        bytes[len - 1 - i] = (num >> (8 * i)) & 0xFF;
    }
}

typedef enum {
    MifareNestedNonceNoTag,
    MifareNestedNonceWeak,
    MifareNestedNonceStatic,
    MifareNestedNonceHard,
} MifareNestedNonceType;

MifareNestedNonceType nested_check_nonce_type(FuriHalNfcTxRxContext* tx_rx, uint8_t blockNo);

struct nonce_info_static {
    uint32_t cuid;
    uint32_t target_nt[2];
    uint32_t target_ks[2];
    bool full;
};

struct nonce_info_hard {
    uint32_t cuid;
    bool static_encrypted;
    bool full;
};

struct nonce_info {
    uint32_t cuid;
    uint32_t target_nt[2];
    uint32_t target_ks[2];
    uint8_t parity[2][4];
    bool full;
};

struct distance_info {
    uint32_t min_prng;
    uint32_t max_prng;
    uint32_t mid_prng;
};

struct nonce_info_static nested_static_nonce_attack(
    FuriHalNfcTxRxContext* tx_rx,
    uint8_t blockNo,
    uint8_t keyType,
    uint8_t targetBlockNo,
    uint8_t targetKeyType,
    uint64_t ui64Key);

struct nonce_info nested_attack(
    FuriHalNfcTxRxContext* tx_rx,
    uint8_t blockNo,
    uint8_t keyType,
    uint8_t targetBlockNo,
    uint8_t targetKeyType,
    uint64_t ui64Key,
    uint32_t distance,
    uint32_t delay);

struct nonce_info_hard nested_hard_nonce_attack(
    FuriHalNfcTxRxContext* tx_rx,
    uint8_t blockNo,
    uint8_t keyType,
    uint8_t targetBlockNo,
    uint8_t targetKeyType,
    uint64_t ui64Key,
    uint32_t* found,
    uint32_t* first_byte_sum,
    Stream* file_stream);

uint32_t nested_calibrate_distance(
    FuriHalNfcTxRxContext* tx_rx,
    uint8_t blockNo,
    uint8_t keyType,
    uint64_t ui64Key,
    uint32_t delay,
    bool full);

struct distance_info nested_calibrate_distance_info(
    FuriHalNfcTxRxContext* tx_rx,
    uint8_t blockNo,
    uint8_t keyType,
    uint64_t ui64Key);

typedef enum {
    NestedCheckKeyNoTag,
    NestedCheckKeyValid,
    NestedCheckKeyInvalid,
} NestedCheckKeyResult;

NestedCheckKeyResult nested_check_key(
    FuriHalNfcTxRxContext* tx_rx,
    uint8_t blockNo,
    uint8_t keyType,
    uint64_t ui64Key);

bool nested_check_block(FuriHalNfcTxRxContext* tx_rx, uint8_t blockNo, uint8_t keyType);

void nested_get_data(FuriHalNfcDevData* dev_data);

bool mifare_classic_authex(
    NestedCrypto1* crypto,
    FuriHalNfcTxRxContext* tx_rx,
    uint32_t uid,
    uint32_t blockNo,
    uint32_t keyType,
    uint64_t ui64Key,
    bool isNested,
    uint32_t* ntptr);

void nfc_activate();

void nfc_deactivate();
