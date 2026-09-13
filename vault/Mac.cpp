#include "Mac.h"

#include <QCryptographicHash>
#include <algorithm>
#include <cstring>

static constexpr int SHA256_BLOCK_SIZE = 64;
static constexpr int SHA256_HASH_SIZE = 32;

QByteArray HmacSha256::name() const
{
    return "HMAC-SHA256";
}

int HmacSha256::macSize() const
{
    return SHA256_HASH_SIZE;
}

QByteArray HmacSha256::compute(const SecureBuffer &key, const QByteArray &data) const
{
    // key を BLOCK_SIZE に揃える（ゼロパディング）
    QByteArray k(SHA256_BLOCK_SIZE, '\0');
    if (key.size() > SHA256_BLOCK_SIZE) {
        QCryptographicHash hash(QCryptographicHash::Sha256);
        hash.addData(reinterpret_cast<const char *>(key.data()), static_cast<int>(key.size()));
        QByteArray hashed = hash.result();
        memcpy(k.data(), hashed.constData(), hashed.size());
    } else {
        memcpy(k.data(), key.data(), key.size());
    }

    QByteArray ipad(SHA256_BLOCK_SIZE, 0);
    QByteArray opad(SHA256_BLOCK_SIZE, 0);
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        ipad[i] = static_cast<char>(k[i] ^ 0x36);
        opad[i] = static_cast<char>(k[i] ^ 0x5c);
    }

    // HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
    QCryptographicHash inner(QCryptographicHash::Sha256);
    inner.addData(ipad);
    inner.addData(data);
    QByteArray innerHash = inner.result();

    QCryptographicHash outer(QCryptographicHash::Sha256);
    outer.addData(opad);
    outer.addData(innerHash);

    return outer.result();
}
