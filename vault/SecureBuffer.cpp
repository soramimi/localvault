#include "SecureBuffer.h"

#include <algorithm>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <string.h>
#else
#include <cstring>
#if defined(__GLIBC__)
#include <sys/mman.h>
#endif
#endif

namespace {

/**
 * @brief コンパイラの最適化を避けて確実にメモリをゼロクリアする
 */
void secure_memzero(void *p, size_t n)
{
    if (!p || n == 0) {
        return;
    }

#if defined(_WIN32)
    SecureZeroMemory(p, n);
#elif defined(__APPLE__)
    memset_s(p, n, 0, n);
#elif defined(__GLIBC__) && defined(__USE_GNU)
    explicit_bzero(p, n);
#else
    // フォールバック: volatile ポインタ経由で最適化を抑止
    volatile uint8_t *vp = static_cast<volatile uint8_t *>(p);
    while (n > 0) {
        *vp++ = 0;
        --n;
    }
#endif
}

bool secure_lock(void *p, size_t n)
{
    if (!p || n == 0) {
        return false;
    }
#if defined(_WIN32)
    return VirtualLock(p, n) != 0;
#elif defined(__APPLE__) || defined(__linux__)
    return mlock(p, n) == 0;
#else
    (void)p;
    (void)n;
    return false;
#endif
}

bool secure_unlock(void *p, size_t n)
{
    if (!p || n == 0) {
        return false;
    }
#if defined(_WIN32)
    return VirtualUnlock(p, n) != 0;
#elif defined(__APPLE__) || defined(__linux__)
    return munlock(p, n) == 0;
#else
    (void)p;
    (void)n;
    return false;
#endif
}

} // namespace

SecureBuffer::SecureBuffer(size_t size)
    : data_(size)
{
}

SecureBuffer::SecureBuffer(const void *data, size_t size)
    : data_(static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data) + size)
{
}

SecureBuffer::SecureBuffer(const uint8_t *begin, const uint8_t *end)
    : data_(begin, end)
{
}

SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept
    : data_(std::move(other.data_))
    , locked_(other.locked_)
{
    other.locked_ = false;
}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept
{
    if (this != &other) {
        if (locked_) {
            secure_unlock(data_.data(), data_.size());
        }
        secure_memzero(data_.data(), data_.size());
        data_ = std::move(other.data_);
        locked_ = other.locked_;
        other.locked_ = false;
    }
    return *this;
}

SecureBuffer::~SecureBuffer()
{
    if (locked_) {
        secure_unlock(data_.data(), data_.size());
    }
    secure_memzero(data_.data(), data_.size());
}

bool SecureBuffer::empty() const
{
    return data_.empty();
}

size_t SecureBuffer::size() const
{
    return data_.size();
}

uint8_t *SecureBuffer::data()
{
    return data_.data();
}

const uint8_t *SecureBuffer::data() const
{
    return data_.data();
}

uint8_t *SecureBuffer::begin()
{
    return data_.data();
}

const uint8_t *SecureBuffer::begin() const
{
    return data_.data();
}

uint8_t *SecureBuffer::end()
{
    return data_.data() + data_.size();
}

const uint8_t *SecureBuffer::end() const
{
    return data_.data() + data_.size();
}

uint8_t &SecureBuffer::operator[](size_t index)
{
    return data_[index];
}

const uint8_t &SecureBuffer::operator[](size_t index) const
{
    return data_[index];
}

void SecureBuffer::resize(size_t size)
{
    if (size < data_.size()) {
        // 縮小時は切り捨てられる領域をゼロクリア
        secure_memzero(data_.data() + size, data_.size() - size);
    }
    data_.resize(size);
}

void SecureBuffer::clear()
{
    secure_memzero(data_.data(), data_.size());
    data_.clear();
}

void SecureBuffer::assign(const void *data, size_t size)
{
    secure_memzero(data_.data(), data_.size());
    data_.assign(static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data) + size);
}

void SecureBuffer::append(const void *data, size_t size)
{
    const uint8_t *begin = static_cast<const uint8_t *>(data);
    data_.insert(data_.end(), begin, begin + size);
}

bool SecureBuffer::lock()
{
    if (locked_ || data_.empty()) {
        return locked_;
    }
    locked_ = secure_lock(data_.data(), data_.size());
    return locked_;
}

void SecureBuffer::unlock()
{
    if (!locked_ || data_.empty()) {
        return;
    }
    secure_unlock(data_.data(), data_.size());
    locked_ = false;
}

bool SecureBuffer::isLocked() const
{
    return locked_;
}
