#ifndef SYSTEMKEYCHAINBACKEND_H
#define SYSTEMKEYCHAINBACKEND_H

#include "../vault/SecretStorage.h"

namespace localvault {

/**
 * @brief OS 標準のセキュアストレージを利用するバックエンド
 *
 * プラットフォーム別に以下を使用:
 * - Linux: libsecret (Secret Service API)
 * - macOS: Keychain Services (Security.framework)
 * - Windows: DPAPI + ローカルファイル
 *
 * std::string / std::vector<char> を使用する。
 */
class SystemKeychainBackend : public ISecretStorageBackend {
public:
	SystemKeychainBackend();
	~SystemKeychainBackend() override;

	bool isAvailable() const override;
	std::string name() const override;
	StorageStatus store(const std::string &key, const Blob &data) override;
	StorageStatus load(const std::string &key, Blob &out) override;
	StorageStatus remove(const std::string &key) override;

private:
	class Impl;
	Impl *impl_;
};

} // namespace localvault

#endif // SYSTEMKEYCHAINBACKEND_H
