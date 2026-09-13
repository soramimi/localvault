#ifndef CHACHA20_H
#define CHACHA20_H

#include <cstddef>
#include <cstdint>

/**
 * @brief ChaCha20 ストリーム暗号 / CSPRNG
 *
 * RFC 8439 に準拠した ChaCha20 実装。
 * デフォルトコンストラクタではランダムな鍵・nonce で CSPRNG として動作する。
 * 鍵・nonce を指定してインスタンス化すれば、ストリーム暗号として使用できる。
 */
class ChaCha20 {
public:
    static constexpr int KEY_SIZE = 32;
    static constexpr int NONCE_SIZE = 12;
    static constexpr int BLOCK_SIZE = 64;

    /**
     * @brief ランダムな鍵・nonce で CSPRNG として初期化
     */
    ChaCha20();

    /**
     * @brief 指定した鍵・nonce でストリーム暗号として初期化
     */
    ChaCha20(const uint8_t key[KEY_SIZE], const uint8_t nonce[NONCE_SIZE]);

    void setKey(const uint8_t key[KEY_SIZE]);
    void setNonce(const uint8_t nonce[NONCE_SIZE]);
    void setKeyAndNonce(const uint8_t key[KEY_SIZE], const uint8_t nonce[NONCE_SIZE]);

    /**
     * @brief カウンターを 0 に戻す
     */
    void reset();

    /**
     * @brief 入力を ChaCha20 キーストリームで XOR する
     */
    void crypt(const uint8_t *input, uint8_t *output, size_t len);

    /**
     * @brief 入力を in-place で XOR する
     */
    void crypt(const uint8_t *input, size_t len);

    /**
     * @brief 次の 32bit 乱数を生成（CSPRNG モード用）
     */
    uint32_t next_u32();

private:
    static constexpr int BUFFER_SIZE = 16;

    uint8_t key_[KEY_SIZE] = {};
    uint8_t nonce_[NONCE_SIZE] = {};
    uint32_t state_[BUFFER_SIZE] = {};
    uint32_t buffer_[BUFFER_SIZE] = {};
    int index_ = 0;

    uint8_t keystream_[BLOCK_SIZE] = {};
    int keystream_index_ = BLOCK_SIZE; // 空を表す

    void seed_random();
    void init_state();
    void generate_keystream_block();
};

#endif // CHACHA20_H
