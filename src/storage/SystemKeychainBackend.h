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
 *
 * Qt 非依存。std::string / std::vector<char> を使用する。
 */
class SystemKeychainBackend : public ISecretStorageBackend {
public:
	SystemKeychainBackend();
	~SystemKeychainBackend() override;

	bool isAvailable() const override;
	std::string name() const override;
	bool store(const std::string &key, const Blob &data) override;
	Blob load(const std::string &key) override;
	bool remove(const std::string &key) override;

private:
	class Impl;
	Impl *impl_;
};

#endif // SYSTEMKEYCHAINBACKEND_H
