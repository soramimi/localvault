#ifndef SECUREBUFFER_H
#define SECUREBUFFER_H

#include <cstddef>
#include <cstdint>
#include <vector>

/**
 * @brief 機密情報を保持するためのセキュアメモリバッファ
 *
 * 通常の std::vector とは異なり、以下の特性を持つ:
 * - 解放時に確実にゼロクリア
 * - 可能であればメモリをロックしてスワップアウトを防止
 * - コピー禁止（ムーブのみ可）
 *
 * Qt 依存なし。QtCore の QByteArray との変換は呼び出し側で行う。
 */
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t size);
    SecureBuffer(const void *data, size_t size);
    SecureBuffer(const uint8_t *begin, const uint8_t *end);
    SecureBuffer(SecureBuffer &&other) noexcept;
    SecureBuffer &operator=(SecureBuffer &&other) noexcept;
    ~SecureBuffer();

    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;

    bool empty() const;
    size_t size() const;

    uint8_t *data();
    const uint8_t *data() const;

    uint8_t *begin();
    const uint8_t *begin() const;
    uint8_t *end();
    const uint8_t *end() const;

    uint8_t &operator[](size_t index);
    const uint8_t &operator[](size_t index) const;

    /** Structural changes are refused while the buffer is memory-locked. */
    bool resize(size_t size);
    void clear();
    bool assign(const void *data, size_t size);
    bool append(const void *data, size_t size);

    /**
     * @brief ページングファイルへの書き出しを防ぐためメモリをロックする
     * @return ロックに成功した場合 true
     */
    bool lock();

    /**
     * @brief lock() でロックしたメモリを解除する
     */
    void unlock();

private:
    std::vector<uint8_t> data_;
    bool locked_ = false;
};

#endif // SECUREBUFFER_H
