#ifndef MAC_H
#define MAC_H

#include "SecureBuffer.h"
#include <QByteArray>

/**
 * @brief メッセージ認証符号（MAC）の抽象インターフェース
 */
class Mac {
public:
    virtual ~Mac() = default;

    virtual QByteArray name() const = 0;
    virtual int macSize() const = 0;

    /**
     * @brief key と data から MAC を計算する
     */
    virtual QByteArray compute(const SecureBuffer &key, const QByteArray &data) const = 0;
};

/**
 * @brief HMAC-SHA256 実装
 *
 * QtCore の QCryptographicHash のみを使用し、自前で HMAC を構成する。
 */
class HmacSha256 : public Mac {
public:
    QByteArray name() const override;
    int macSize() const override;
    QByteArray compute(const SecureBuffer &key, const QByteArray &data) const override;
};

#endif // MAC_H
