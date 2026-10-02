#ifndef SECRETSTORAGE_H
#define SECRETSTORAGE_H

#include <string>
#include <vector>

/**
 * @brief セキュアストレージバックエンドの抽象インターフェース
 *
 * Vault はこのインターフェースを通じて EMK（Encrypted Master Key）等の
 * 機密データを保存・読み出しする。
 *
 * Qt 非依存。std::vector<char> でバイナリ blob、std::string で識別キーを扱う。
 */
using Blob = std::vector<char>;

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
	virtual std::string name() const = 0;

	/**
	 * @brief key に対応する data を保存する
	 */
	virtual bool store(const std::string &key, const Blob &data) = 0;

	/**
	 * @brief key に対応する data を読み出す
	 * @return データが存在しない場合は空の Blob
	 */
	virtual Blob load(const std::string &key) = 0;

	/**
	 * @brief key に対応するデータを削除する
	 */
	virtual bool remove(const std::string &key) = 0;
};

#endif // SECRETSTORAGE_H
