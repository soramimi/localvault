#ifndef VAULT_H
#define VAULT_H

#include "SecretStorage.h"
#include "SecureBuffer.h"
#include <cstdint>
#include <string>

/**
 * @brief ローカル Vault（機密情報管理コア）
 *
 * 2段階鍵体系（MK / KEK / EMK）を採用。
 * - MK: ランダム 256bit。データの暗号化に使用
 * - KEK: PIN から Argon2id で導出
 * - EMK: KEK で暗号化された MK。ISecretStorageBackend に保存
 *
 * Qt 非依存。std::vector<char> / std::string を使用する。
 */
class Vault {
private:
	static constexpr int VERSION = 2;
	static constexpr int SALT_SIZE = 16;
	static constexpr int NONCE_SIZE = 24;
	static constexpr int MK_SIZE = 32;
	static constexpr int TAG_SIZE = 16;
	// libsodium crypto_pwhash_OPSLIMIT_MODERATE / MEMLIMIT_MODERATE に相当
	static constexpr uint32_t ARGON2_OPSLIMIT = 3;
	static constexpr uint32_t ARGON2_MEMLIMIT = 256 * 1024 * 1024;

	ISecretStorageBackend *backend_;
	std::string emkKey_;
	SecureBuffer mk_;
	bool unlocked_ = false;

	SecureBuffer deriveKek(const SecureBuffer &pin, const Blob &salt, uint32_t opsLimit, uint32_t memLimit) const;

	Blob generateRandom(int length) const;
	Blob buildEmk(const SecureBuffer &mk, const SecureBuffer &kek, const Blob &salt);
	bool parseEmk(const Blob &emk, const SecureBuffer &pin, SecureBuffer &mk);

public:
	/**
	 * @param backend EMK を保存するバックエンド。生存期間中は有効なポインタであること
	 * @param emkKey バックエンド内での EMK の識別キー
	 */
	Vault(ISecretStorageBackend *backend, const std::string &emkKey = "vault_emk");
	~Vault();

	bool isAvailable() const;
	bool isSetup() const;
	bool isUnlocked() const;

	/** バックエンド内でEMKを識別するキー。呼び出し元がバックエンドを直接操作する際に使用する */
	std::string emkKey() const { return emkKey_; }

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
	Blob encrypt(const Blob &plain);

	/**
	 * @brief 暗号文を復号する。unlock 済みである必要がある
	 *
	 * 平文は SecureBuffer に返され、使用後は明示的に clear() すること。
	 */
	SecureBuffer decryptToSecureBuffer(const Blob &cipher);

	/**
	 * @brief PIN を変更する
	 */
	bool changePin(const SecureBuffer &oldPin, const SecureBuffer &newPin);

	/**
	 * @brief 既存EMKを削除して新しいPINで再セットアップする。
	 *
	 * 既存のMKで暗号化されたデータは復号不能になる不可逆操作。
	 */
	bool reset(const SecureBuffer &newPin);
};

#endif // VAULT_H
