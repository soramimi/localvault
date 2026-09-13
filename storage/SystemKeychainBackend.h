#ifndef SYSTEMKEYCHAINBACKEND_H
#define SYSTEMKEYCHAINBACKEND_H

#include "../vault/SecretStorage.h"

/**
 * @brief OS 標準のセキュアストレージを利用するバックエンド
 *
 * プラットフォーム別に以下を使用:
 * - Linux: libsecret (Secret Service API)
 * - macOS: Keychain Services (Security.framework)
 * - Windows: DPAPI + ローカルファイル
 */
class SystemKeychainBackend : public ISecretStorageBackend {
public:
    SystemKeychainBackend();
    ~SystemKeychainBackend() override;

    bool isAvailable() const override;
    QString name() const override;
    bool store(const QString &key, const QByteArray &data) override;
    QByteArray load(const QString &key) override;
    bool remove(const QString &key) override;

private:
    class Impl;
    Impl *impl_;
};

#endif // SYSTEMKEYCHAINBACKEND_H
