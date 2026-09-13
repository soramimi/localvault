#ifndef SECRETSTORAGE_H
#define SECRETSTORAGE_H

#include <QByteArray>
#include <QString>

/**
 * @brief セキュアストレージバックエンドの抽象インターフェース
 *
 * Vault はこのインターフェースを通じて EMK（Encrypted Master Key）等の
 * 機密データを保存・読み出しする。
 */
class ISecretStorageBackend {
public:
	virtual ~ISecretStorageBackend() = default;
	
	/**
	 * @brief このバックエンドが利用可能かを返す
	 */
	virtual bool isAvailable() const = 0;
	
	/**
	 * @brief バックエンドの識別名
	 */
	virtual QString name() const = 0;
	
	/**
	 * @brief key に対応する data を保存する
	 */
	virtual bool store(const QString &key, const QByteArray &data) = 0;
	
	/**
	 * @brief key に対応する data を読み出す
	 * @return データが存在しない場合は空の QByteArray
	 */
	virtual QByteArray load(const QString &key) = 0;
	
	/**
	 * @brief key に対応するデータを削除する
	 */
	virtual bool remove(const QString &key) = 0;
};

#endif // SECRETSTORAGE_H
