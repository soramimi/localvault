#include "Vault.h"

#include <algorithm>
#include <cstring>
#include <sodium.h>

namespace {

constexpr char MAGIC[] = "VLT2";
constexpr int MAGIC_SIZE = 4;
constexpr uint8_t EMK_RECORD = 1;
constexpr uint8_t DATA_RECORD = 2;
constexpr uint8_t XCHACHA20_POLY1305 = 1;
constexpr uint8_t ARGON2ID = 2;
constexpr int SALT_SIZE = 16;
constexpr int NONCE_SIZE = 24;
constexpr int MK_SIZE = 32;
constexpr int TAG_SIZE = 16;
constexpr int EMK_HEADER_SIZE = MAGIC_SIZE + 1 + 1 + 1 + 1 + 4 + 4 + 1 + SALT_SIZE;
constexpr int DATA_HEADER_SIZE = MAGIC_SIZE + 1 + 1 + 1;
constexpr uint32_t MIN_ARGON2_OPSLIMIT = 2;
constexpr uint32_t MAX_ARGON2_OPSLIMIT = 10;
constexpr uint32_t MIN_ARGON2_MEMLIMIT = 64 * 1024 * 1024;
constexpr uint32_t MAX_ARGON2_MEMLIMIT = 1024 * 1024 * 1024;

bool sodiumReady()
{
	static const bool ready = sodium_init() >= 0;
	return ready;
}

void appendU32(Blob &out, uint32_t value)
{
	out.push_back(static_cast<char>((value >> 24) & 0xff));
	out.push_back(static_cast<char>((value >> 16) & 0xff));
	out.push_back(static_cast<char>((value >> 8) & 0xff));
	out.push_back(static_cast<char>(value & 0xff));
}

uint32_t readU32(const Blob &in, size_t offset)
{
	const auto *p = reinterpret_cast<const unsigned char *>(in.data() + offset);
	return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

} // namespace

Vault::Vault(ISecretStorageBackend *backend, const std::string &emkKey)
	: backend_(backend)
	, emkKey_(emkKey)
{
}

Vault::~Vault()
{
	lock();
}

bool Vault::isAvailable() const
{
	return backend_ && backend_->isAvailable() && sodiumReady();
}

bool Vault::isSetup() const
{
	return backend_ && !backend_->load(emkKey_).empty();
}

bool Vault::isUnlocked() const
{
	return unlocked_ && mk_.size() == MK_SIZE;
}

void Vault::lock()
{
	mk_.clear();
	unlocked_ = false;
}

SecureBuffer Vault::deriveKek(const SecureBuffer &pin, const Blob &salt, uint32_t opsLimit, uint32_t memLimit) const
{
	if (pin.empty()) return { };
	if (salt.size() != crypto_pwhash_SALTBYTES) return { };
	if (opsLimit < MIN_ARGON2_OPSLIMIT) return { };
	if (opsLimit > MAX_ARGON2_OPSLIMIT) return { };
	if (memLimit < MIN_ARGON2_MEMLIMIT) return { };
	if (memLimit > MAX_ARGON2_MEMLIMIT) return { };

	SecureBuffer kek(MK_SIZE);
	if (crypto_pwhash(kek.data(), kek.size(), reinterpret_cast<const char *>(pin.data()), pin.size(), reinterpret_cast<const unsigned char *>(salt.data()), opsLimit, memLimit, crypto_pwhash_ALG_ARGON2ID13) != 0
		|| !kek.lock()) {
		kek.clear();
	}
	return kek;
}

Blob Vault::generateRandom(int length) const
{
	if (!sodiumReady() || length < 0) return { };
	Blob out(static_cast<size_t>(length));
	randombytes_buf(out.data(), out.size());
	return out;
}

Blob Vault::buildEmk(const SecureBuffer &mk, const SecureBuffer &kek, const Blob &salt)
{
	if (!sodiumReady() || mk.size() != MK_SIZE || kek.size() != MK_SIZE || salt.size() != SALT_SIZE) return { };
	Blob header;
	header.reserve(EMK_HEADER_SIZE);
	header.insert(header.end(), MAGIC, MAGIC + MAGIC_SIZE);
	header.push_back(static_cast<char>(VERSION));
	header.push_back(static_cast<char>(EMK_RECORD));
	header.push_back(static_cast<char>(XCHACHA20_POLY1305));
	header.push_back(static_cast<char>(ARGON2ID));
	appendU32(header, ARGON2_OPSLIMIT);
	appendU32(header, ARGON2_MEMLIMIT);
	header.push_back(static_cast<char>(SALT_SIZE));
	header.insert(header.end(), salt.begin(), salt.end());
	const Blob nonce = generateRandom(NONCE_SIZE);
	Blob encrypted(MK_SIZE + TAG_SIZE);
	unsigned long long encryptedLen = 0;
	if (crypto_aead_xchacha20poly1305_ietf_encrypt(reinterpret_cast<unsigned char *>(encrypted.data()),
			&encryptedLen, mk.data(),
			MK_SIZE,
			reinterpret_cast<const unsigned char *>(header.data()),
			header.size(),
			nullptr,
			reinterpret_cast<const unsigned char *>(nonce.data()),
			kek.data())
		!= 0) {
		return { };
	}
	encrypted.resize(static_cast<size_t>(encryptedLen));
	Blob result;
	result.reserve(header.size() + nonce.size() + encrypted.size());
	result.insert(result.end(), header.begin(), header.end());
	result.insert(result.end(), nonce.begin(), nonce.end());
	result.insert(result.end(), encrypted.begin(), encrypted.end());
	return result;
}

bool Vault::parseEmk(const Blob &emk, const SecureBuffer &pin, SecureBuffer &mk)
{
	if (!sodiumReady() || emk.size() != static_cast<size_t>(EMK_HEADER_SIZE + NONCE_SIZE + MK_SIZE + TAG_SIZE)
		|| !std::equal(emk.begin(), emk.begin() + MAGIC_SIZE, MAGIC)
		|| static_cast<uint8_t>(emk[MAGIC_SIZE]) != VERSION
		|| static_cast<uint8_t>(emk[MAGIC_SIZE + 1]) != EMK_RECORD
		|| static_cast<uint8_t>(emk[MAGIC_SIZE + 2]) != XCHACHA20_POLY1305
		|| static_cast<uint8_t>(emk[MAGIC_SIZE + 3]) != ARGON2ID
		|| static_cast<uint8_t>(emk[MAGIC_SIZE + 12]) != SALT_SIZE) {
		return false;
	}
	const Blob salt(emk.begin() + MAGIC_SIZE + 13, emk.begin() + MAGIC_SIZE + 13 + SALT_SIZE);
	SecureBuffer kek = deriveKek(pin, salt, readU32(emk, MAGIC_SIZE + 4), readU32(emk, MAGIC_SIZE + 8));
	if (kek.empty()) return false;
	const Blob header(emk.begin(), emk.begin() + EMK_HEADER_SIZE);
	const Blob nonce(emk.begin() + EMK_HEADER_SIZE, emk.begin() + EMK_HEADER_SIZE + NONCE_SIZE);
	const Blob encrypted(emk.begin() + EMK_HEADER_SIZE + NONCE_SIZE, emk.end());
	SecureBuffer result(MK_SIZE);
	unsigned long long resultLen = 0;
	const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(result.data(), &resultLen, nullptr,
		reinterpret_cast<const unsigned char *>(encrypted.data()), encrypted.size(),
		reinterpret_cast<const unsigned char *>(header.data()), header.size(),
		reinterpret_cast<const unsigned char *>(nonce.data()), kek.data());
	kek.clear();
	if (rc != 0 || resultLen != MK_SIZE || !result.lock()) {
		result.clear();
		return false;
	}
	mk = std::move(result);
	return true;
}

bool Vault::setup(const SecureBuffer &pin)
{
	if (!isAvailable() || pin.empty() || isSetup()) return false;
	const Blob salt = generateRandom(SALT_SIZE);
	SecureBuffer kek = deriveKek(pin, salt, ARGON2_OPSLIMIT, ARGON2_MEMLIMIT);
	SecureBuffer master(MK_SIZE);
	if (kek.empty() || !master.lock()) return false;
	randombytes_buf(master.data(), MK_SIZE);
	const Blob emk = buildEmk(master, kek, salt);
	kek.clear();
	if (emk.empty() || !backend_->store(emkKey_, emk)) return false;
	mk_ = std::move(master);
	unlocked_ = true;
	return true;
}

bool Vault::unlock(const SecureBuffer &pin)
{
	if (!isAvailable() || pin.empty()) return false;
	SecureBuffer master;
	if (!parseEmk(backend_->load(emkKey_), pin, master)) return false;
	lock();
	mk_ = std::move(master);
	unlocked_ = true;
	return true;
}

Blob Vault::encrypt(const Blob &plain)
{
	if (!isUnlocked() || !sodiumReady()) return { };
	Blob header;
	header.reserve(DATA_HEADER_SIZE);
	header.insert(header.end(), MAGIC, MAGIC + MAGIC_SIZE);
	header.push_back(static_cast<char>(VERSION));
	header.push_back(static_cast<char>(DATA_RECORD));
	header.push_back(static_cast<char>(XCHACHA20_POLY1305));
	const Blob nonce = generateRandom(NONCE_SIZE);
	Blob encrypted(plain.size() + TAG_SIZE);
	unsigned long long encryptedLen = 0;
	if (crypto_aead_xchacha20poly1305_ietf_encrypt(reinterpret_cast<unsigned char *>(encrypted.data()), &encryptedLen,
			reinterpret_cast<const unsigned char *>(plain.data()), plain.size(),
			reinterpret_cast<const unsigned char *>(header.data()), header.size(), nullptr,
			reinterpret_cast<const unsigned char *>(nonce.data()), mk_.data())
		!= 0) return { };
	encrypted.resize(static_cast<size_t>(encryptedLen));
	Blob result;
	result.reserve(header.size() + nonce.size() + encrypted.size());
	result.insert(result.end(), header.begin(), header.end());
	result.insert(result.end(), nonce.begin(), nonce.end());
	result.insert(result.end(), encrypted.begin(), encrypted.end());
	return result;
}

SecureBuffer Vault::decryptToSecureBuffer(const Blob &cipher)
{
	if (!isUnlocked() || !sodiumReady() || cipher.size() < static_cast<size_t>(DATA_HEADER_SIZE + NONCE_SIZE + TAG_SIZE)
		|| !std::equal(cipher.begin(), cipher.begin() + MAGIC_SIZE, MAGIC)
		|| static_cast<uint8_t>(cipher[MAGIC_SIZE]) != VERSION
		|| static_cast<uint8_t>(cipher[MAGIC_SIZE + 1]) != DATA_RECORD
		|| static_cast<uint8_t>(cipher[MAGIC_SIZE + 2]) != XCHACHA20_POLY1305) return { };
	const Blob header(cipher.begin(), cipher.begin() + DATA_HEADER_SIZE);
	const Blob nonce(cipher.begin() + DATA_HEADER_SIZE, cipher.begin() + DATA_HEADER_SIZE + NONCE_SIZE);
	const Blob encrypted(cipher.begin() + DATA_HEADER_SIZE + NONCE_SIZE, cipher.end());
	if (encrypted.size() < TAG_SIZE) {
		return { };
	}
	SecureBuffer plain(encrypted.size() - TAG_SIZE);
	unsigned long long plainLen = 0;
	if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain.data(), &plainLen, nullptr,
			reinterpret_cast<const unsigned char *>(encrypted.data()), encrypted.size(),
			reinterpret_cast<const unsigned char *>(header.data()), header.size(),
			reinterpret_cast<const unsigned char *>(nonce.data()), mk_.data())
			!= 0
		|| !plain.resize(static_cast<size_t>(plainLen)) || !plain.lock()) {
		plain.clear();
		return { };
	}
	return plain;
}

bool Vault::changePin(const SecureBuffer &oldPin, const SecureBuffer &newPin)
{
	if (!isUnlocked() || newPin.empty()) return false;
	SecureBuffer verifiedMaster;
	if (!parseEmk(backend_->load(emkKey_), oldPin, verifiedMaster)) return false;
	const Blob salt = generateRandom(SALT_SIZE);
	SecureBuffer newKek = deriveKek(newPin, salt, ARGON2_OPSLIMIT, ARGON2_MEMLIMIT);
	const Blob newEmk = buildEmk(verifiedMaster, newKek, salt);
	verifiedMaster.clear();
	newKek.clear();
	return !newEmk.empty() && backend_->store(emkKey_, newEmk);
}

bool Vault::reset(const SecureBuffer &newPin)
{
	if (!isAvailable() || newPin.empty()) return false;

	if (isSetup() && !backend_->remove(emkKey_)) return false;
	lock();
	return setup(newPin);
}
