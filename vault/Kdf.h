#ifndef KDF_H
#define KDF_H

#include "SecureBuffer.h"
#include <QByteArray>

/**
 * @brief 鍵導出関数（KDF）の抽象インターフェース
 */
class Kdf {
public:
    virtual ~Kdf() = default;

    virtual QByteArray name() const = 0;

    /**
     * @brief password と salt から keyLen バイトの鍵を導出する
     */
    virtual SecureBuffer derive(const SecureBuffer &password, const QByteArray &salt, int keyLen) const = 0;
};

/**
 * @brief PBKDF2-SHA256 実装
 */
class Pbkdf2Sha256 : public Kdf {
public:
    explicit Pbkdf2Sha256(int iterations = 100000);

    QByteArray name() const override;
    SecureBuffer derive(const SecureBuffer &password, const QByteArray &salt, int keyLen) const override;

    int iterations() const;

private:
    int iterations_;
};

#endif // KDF_H
