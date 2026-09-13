#include "ChaCha20.h"

#include <QRandomGenerator>
#include <algorithm>
#include <cstring>

static uint32_t rotl(uint32_t v, int n)
{
    return (v << n) | (v >> (32 - n));
}

static void quarter_round(uint32_t *x, int a, int b, int c, int d)
{
    x[a] += x[b];
    x[d] ^= x[a];
    x[d] = rotl(x[d], 16);
    x[c] += x[d];
    x[b] ^= x[c];
    x[b] = rotl(x[b], 12);
    x[a] += x[b];
    x[d] ^= x[a];
    x[d] = rotl(x[d], 8);
    x[c] += x[d];
    x[b] ^= x[c];
    x[b] = rotl(x[b], 7);
}

static void chacha20_block(const uint32_t in[16], uint32_t out[16])
{
    uint32_t x[16];
    memcpy(x, in, sizeof(x));

    for (int i = 0; i < 10; i++) {
        quarter_round(x, 0, 4, 8, 12);
        quarter_round(x, 1, 5, 9, 13);
        quarter_round(x, 2, 6, 10, 14);
        quarter_round(x, 3, 7, 11, 15);
        quarter_round(x, 0, 5, 10, 15);
        quarter_round(x, 1, 6, 11, 12);
        quarter_round(x, 2, 7, 8, 13);
        quarter_round(x, 3, 4, 9, 14);
    }

    for (int i = 0; i < 16; i++) {
        out[i] = x[i] + in[i];
    }
}

static void chacha20_init_state(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter)
{
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < 8; i++) {
        state[4 + i] = key[i * 4 + 0] | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24);
    }

    state[12] = counter;

    for (int i = 0; i < 3; i++) {
        state[13 + i] = nonce[i * 4 + 0] | (nonce[i * 4 + 1] << 8) | (nonce[i * 4 + 2] << 16) | (nonce[i * 4 + 3] << 24);
    }
}

static void fill_random(void *p, size_t len)
{
    uint8_t *out = static_cast<uint8_t *>(p);
    while (len > 0) {
        quint32 value = QRandomGenerator::system()->generate();
        size_t chunk = std::min(len, sizeof(quint32));
        memcpy(out, &value, chunk);
        out += chunk;
        len -= chunk;
    }
}

void ChaCha20::seed_random()
{
    fill_random(key_, sizeof(key_));
    fill_random(nonce_, sizeof(nonce_));
}

void ChaCha20::init_state()
{
    chacha20_init_state(state_, key_, nonce_, 0);
    index_ = 0;
    keystream_index_ = BLOCK_SIZE;
}

void ChaCha20::generate_keystream_block()
{
    chacha20_block(state_, buffer_);

    // little-endian バイト列としてシリアライズ
    for (int i = 0; i < BUFFER_SIZE; i++) {
        keystream_[i * 4 + 0] = buffer_[i] & 0xff;
        keystream_[i * 4 + 1] = (buffer_[i] >> 8) & 0xff;
        keystream_[i * 4 + 2] = (buffer_[i] >> 16) & 0xff;
        keystream_[i * 4 + 3] = (buffer_[i] >> 24) & 0xff;
    }

    state_[12]++;
    keystream_index_ = 0;
}

ChaCha20::ChaCha20()
{
    seed_random();
    init_state();
}

ChaCha20::ChaCha20(const uint8_t key[KEY_SIZE], const uint8_t nonce[NONCE_SIZE])
{
    setKeyAndNonce(key, nonce);
}

void ChaCha20::setKey(const uint8_t key[KEY_SIZE])
{
    memcpy(key_, key, KEY_SIZE);
}

void ChaCha20::setNonce(const uint8_t nonce[NONCE_SIZE])
{
    memcpy(nonce_, nonce, NONCE_SIZE);
}

void ChaCha20::setKeyAndNonce(const uint8_t key[KEY_SIZE], const uint8_t nonce[NONCE_SIZE])
{
    setKey(key);
    setNonce(nonce);
    init_state();
}

void ChaCha20::reset()
{
    init_state();
}

void ChaCha20::crypt(const uint8_t *input, uint8_t *output, size_t len)
{
    while (len > 0) {
        if (keystream_index_ >= BLOCK_SIZE) {
            generate_keystream_block();
        }
        size_t chunk = std::min(len, static_cast<size_t>(BLOCK_SIZE - keystream_index_));
        for (size_t i = 0; i < chunk; i++) {
            output[i] = input[i] ^ keystream_[keystream_index_ + i];
        }
        input += chunk;
        output += chunk;
        keystream_index_ += chunk;
        len -= chunk;
    }
}

void ChaCha20::crypt(const uint8_t *input, size_t len)
{
    crypt(input, const_cast<uint8_t *>(input), len);
}

uint32_t ChaCha20::next_u32()
{
    if (index_ == 0) {
        chacha20_block(state_, buffer_);
        state_[12]++;
    }
    uint32_t value = buffer_[index_];
    index_ = (index_ + 1) % BUFFER_SIZE;
    return value;
}
