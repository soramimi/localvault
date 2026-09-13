#ifndef VAULT_H
#define VAULT_H

#include "SecretStorage.h"
#include "SecureBuffer.h"
#include <QByteArray>
#include <QString>

class Kdf;
class Mac;

/**
 * @brief ローカル Vault（機密情報管理コア）
 *
 * 2段階鍵体系（MK / KEK / EMK）を採用。
 * - MK: ランダム 256bit。データの暗号化に使用
 * - KEK: PIN から PBKDF2-SHA256 で導出
 * - EMK: KEK で暗号化された MK。ISecretStorageBackend に保存
 */
class Vault {
public:
    /**
     * @param backend EMK を保存するバックエンド。生存期間中は有効なポインタであること
     * @param emkKey バックエンド内での EMK の識別キー
     */
    Vault(ISecretStorageBackend *backend, const QString &emkKey = QStringLiteral("vault_emk"));
    ~Vault();

    bool isAvailable() const;
    bool isSetup() const;
    bool isUnlocked() const;

    /**
     * @brief 初回セットアップ。PIN から KEK を導出し、MK を生成・暗号化して保存する
     */
    bool setup(const SecureBuffer &pin);

    /**
     * @brief PIN で Vault を解除し、MK をメモリ上に復号する
     */
    bool unlock(const SecureBuffer &pin);

    /**
     * @brief メモリ上の MK を消去する
     */
    void lock();

    /**
     * @brief 平文を暗号化する。unlock 済みである必要がある
     */
    QByteArray encrypt(const QByteArray &plain);

    /**
     * @brief 暗号文を復号する。unlock 済みである必要がある
     */
    QByteArray decrypt(const QByteArray &cipher);

    /**
     * @brief PIN を変更する
     */
    bool changePin(const SecureBuffer &oldPin, const SecureBuffer &newPin);

private:
    static constexpr int VERSION = 1;
    static constexpr int SALT_SIZE = 16;
    static constexpr int NONCE_SIZE = 12;
    static constexpr int MK_SIZE = 32;
    static constexpr int TAG_SIZE = 32;

    ISecretStorageBackend *backend_;
    QString emkKey_;
    SecureBuffer mk_;
    bool unlocked_ = false;

    bool hasEmk() const;
    SecureBuffer deriveKek(const SecureBuffer &pin, const QByteArray &salt) const;

    QByteArray generateRandom(int length) const;
    QByteArray buildEmk(const SecureBuffer &mk, const SecureBuffer &kek, const QByteArray &salt, const QByteArray &nonce);
    bool parseEmk(const QByteArray &emk, const SecureBuffer &kek, SecureBuffer &mk);

    QByteArray encryptWithMk(const QByteArray &plain);
    bool decryptWithMk(const QByteArray &cipher, QByteArray &plain);

};

#endif // VAULT_H
