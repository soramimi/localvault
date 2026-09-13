#ifndef FILEBACKEND_H
#define FILEBACKEND_H

#include "../vault/SecretStorage.h"
#include <QString>

/**
 * @brief ファイルベースのセキュアストレージバックエンド
 *
 * OS のセキュアストレージが利用できない環境のフォールバック。
 * EMK をローカルファイルに保存し、可能な限り 0600 等の厳格な
 * パーミッションを設定する。
 */
class FileBackend : public ISecretStorageBackend {
public:
    explicit FileBackend(const QString &directory = QString());

    bool isAvailable() const override;
    QString name() const override;
    bool store(const QString &key, const QByteArray &data) override;
    QByteArray load(const QString &key) override;
    bool remove(const QString &key) override;

    QString directory() const;

private:
    QString directory_;

    QString filePathForKey(const QString &key) const;
    static QString sanitizeKey(const QString &key);
};

#endif // FILEBACKEND_H
