#ifndef FILEBACKEND_H
#define FILEBACKEND_H

#include "../vault/SecretStorage.h"
#include <filesystem>
#include <string>

/**
 * @brief ファイルベースのセキュアストレージバックエンド
 *
 * OS のセキュアストレージが利用できない環境のフォールバック。
 * EMK をローカルファイルに保存し、可能な限り 0600 等の厳格な
 * パーミッションを設定する。
 *
 * Qt 非依存。std::filesystem::path と標準 C++ ライブラリで実装。
 */
class FileBackend : public ISecretStorageBackend {
public:
	explicit FileBackend(const std::filesystem::path &directory = { });

	bool isAvailable() const override;
	std::string name() const override;
	bool store(const std::string &key, const Blob &data) override;
	Blob load(const std::string &key) override;
	bool remove(const std::string &key) override;

private:
	std::filesystem::path directory_;

	std::filesystem::path filePathForKey(const std::string &key) const;
	static std::string sanitizeKey(const std::string &key);
	static std::filesystem::path defaultConfigDirectory();
};

#endif // FILEBACKEND_H
