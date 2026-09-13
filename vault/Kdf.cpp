#include "Kdf.h"

#include "Mac.h"
#include <algorithm>
#include <cstring>

static constexpr int SHA256_HASH_SIZE = 32;

Pbkdf2Sha256::Pbkdf2Sha256(int iterations)
    : iterations_(iterations)
{
    if (iterations_ < 1) {
        iterations_ = 1;
    }
}

QByteArray Pbkdf2Sha256::name() const
{
    return "PBKDF2-SHA256";
}

int Pbkdf2Sha256::iterations() const
{
    return iterations_;
}

SecureBuffer Pbkdf2Sha256::derive(const SecureBuffer &password, const QByteArray &salt, int keyLen) const
{
    if (keyLen <= 0) {
        return SecureBuffer();
    }

    HmacSha256 hmac;
    const int blocks = (keyLen + SHA256_HASH_SIZE - 1) / SHA256_HASH_SIZE;
    SecureBuffer out(keyLen);

    for (int i = 1; i <= blocks; i++) {
        // salt || INT_32_BE(i)
        QByteArray u = salt;
        u.append(static_cast<char>((i >> 24) & 0xff));
        u.append(static_cast<char>((i >> 16) & 0xff));
        u.append(static_cast<char>((i >> 8) & 0xff));
        u.append(static_cast<char>(i & 0xff));

        QByteArray t = hmac.compute(password, u);
        u = t;

        for (int j = 1; j < iterations_; j++) {
            u = hmac.compute(password, u);
            for (int k = 0; k < t.size(); k++) {
                t[k] = static_cast<char>(t[k] ^ u[k]);
            }
        }

        const int offset = (i - 1) * SHA256_HASH_SIZE;
        const int copyLen = std::min(SHA256_HASH_SIZE, keyLen - offset);
        memcpy(out.data() + offset, t.constData(), copyLen);
    }

    out.lock();
    return out;
}
