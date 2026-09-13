#include "Vault.h"

#include <sodium.h>

namespace {
constexpr char MAGIC[] = "VLT2";
constexpr int MAGIC_SIZE = 4;
constexpr quint8 EMK_RECORD = 1, DATA_RECORD = 2, XCHACHA20_POLY1305 = 1, ARGON2ID = 2;
constexpr int SALT_SIZE = 16, NONCE_SIZE = 24, MK_SIZE = 32, TAG_SIZE = 16;
constexpr int EMK_HEADER_SIZE = MAGIC_SIZE + 1 + 1 + 1 + 1 + 4 + 4 + 1 + SALT_SIZE;
constexpr int DATA_HEADER_SIZE = MAGIC_SIZE + 1 + 1 + 1;
constexpr quint32 MIN_ARGON2_OPSLIMIT = 3, MAX_ARGON2_OPSLIMIT = 10;
constexpr quint32 MIN_ARGON2_MEMLIMIT = 64 * 1024 * 1024, MAX_ARGON2_MEMLIMIT = 1024 * 1024 * 1024;

bool sodiumReady()
{
    static const bool ready = sodium_init() >= 0;
    return ready;
}

void appendU32(QByteArray &out, quint32 value)
{
    out.append(static_cast<char>((value >> 24) & 0xff));
    out.append(static_cast<char>((value >> 16) & 0xff));
    out.append(static_cast<char>((value >> 8) & 0xff));
    out.append(static_cast<char>(value & 0xff));
}

quint32 readU32(const QByteArray &in, int offset)
{
    const auto *p = reinterpret_cast<const unsigned char *>(in.constData() + offset);
    return (static_cast<quint32>(p[0]) << 24) | (static_cast<quint32>(p[1]) << 16)
        | (static_cast<quint32>(p[2]) << 8) | p[3];
}
}

Vault::Vault(ISecretStorageBackend *backend, const QString &emkKey) : backend_(backend), emkKey_(emkKey) {}
Vault::~Vault() { lock(); }
bool Vault::isAvailable() const { return backend_ && backend_->isAvailable() && sodiumReady(); }
bool Vault::isSetup() const { return backend_ && !backend_->load(emkKey_).isEmpty(); }
bool Vault::isUnlocked() const { return unlocked_ && mk_.size() == MK_SIZE; }

void Vault::lock()
{
    mk_.clear();
    unlocked_ = false;
}

SecureBuffer Vault::deriveKek(const SecureBuffer &pin, const QByteArray &salt, quint32 opsLimit, quint32 memLimit) const
{
    if (pin.empty() || salt.size() != crypto_pwhash_SALTBYTES || opsLimit < MIN_ARGON2_OPSLIMIT
        || opsLimit > MAX_ARGON2_OPSLIMIT || memLimit < MIN_ARGON2_MEMLIMIT || memLimit > MAX_ARGON2_MEMLIMIT) return {};
    SecureBuffer kek(MK_SIZE);
    if (crypto_pwhash(kek.data(), kek.size(), reinterpret_cast<const char *>(pin.data()), pin.size(),
            reinterpret_cast<const unsigned char *>(salt.constData()), opsLimit, memLimit,
            crypto_pwhash_ALG_ARGON2ID13) != 0 || !kek.lock()) {
        kek.clear();
    }
    return kek;
}

QByteArray Vault::generateRandom(int length) const
{
    if (!sodiumReady() || length < 0) return {};
    QByteArray out(length, Qt::Uninitialized);
    randombytes_buf(out.data(), static_cast<size_t>(out.size()));
    return out;
}

QByteArray Vault::buildEmk(const SecureBuffer &mk, const SecureBuffer &kek, const QByteArray &salt)
{
    if (!sodiumReady() || mk.size() != MK_SIZE || kek.size() != MK_SIZE || salt.size() != SALT_SIZE) return {};
    QByteArray header(MAGIC, MAGIC_SIZE);
    header.append(static_cast<char>(VERSION));
    header.append(static_cast<char>(EMK_RECORD));
    header.append(static_cast<char>(XCHACHA20_POLY1305));
    header.append(static_cast<char>(ARGON2ID));
    appendU32(header, ARGON2_OPSLIMIT);
    appendU32(header, ARGON2_MEMLIMIT);
    header.append(static_cast<char>(SALT_SIZE));
    header.append(salt);
    const QByteArray nonce = generateRandom(NONCE_SIZE);
    QByteArray encrypted(MK_SIZE + TAG_SIZE, Qt::Uninitialized);
    unsigned long long encryptedLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(reinterpret_cast<unsigned char *>(encrypted.data()), &encryptedLen,
            mk.data(), MK_SIZE, reinterpret_cast<const unsigned char *>(header.constData()), header.size(), nullptr,
            reinterpret_cast<const unsigned char *>(nonce.constData()), kek.data()) != 0) return {};
    encrypted.resize(static_cast<int>(encryptedLen));
    return header + nonce + encrypted;
}

bool Vault::parseEmk(const QByteArray &emk, const SecureBuffer &pin, SecureBuffer &mk)
{
    if (!sodiumReady() || emk.size() != EMK_HEADER_SIZE + NONCE_SIZE + MK_SIZE + TAG_SIZE
        || !emk.startsWith(QByteArray(MAGIC, MAGIC_SIZE)) || static_cast<quint8>(emk[MAGIC_SIZE]) != VERSION
        || static_cast<quint8>(emk[MAGIC_SIZE + 1]) != EMK_RECORD || static_cast<quint8>(emk[MAGIC_SIZE + 2]) != XCHACHA20_POLY1305
        || static_cast<quint8>(emk[MAGIC_SIZE + 3]) != ARGON2ID || static_cast<quint8>(emk[MAGIC_SIZE + 12]) != SALT_SIZE) return false;
    const QByteArray salt = emk.mid(MAGIC_SIZE + 13, SALT_SIZE);
    SecureBuffer kek = deriveKek(pin, salt, readU32(emk, MAGIC_SIZE + 4), readU32(emk, MAGIC_SIZE + 8));
    if (kek.empty()) return false;
    const QByteArray header = emk.left(EMK_HEADER_SIZE);
    const QByteArray nonce = emk.mid(EMK_HEADER_SIZE, NONCE_SIZE);
    const QByteArray encrypted = emk.mid(EMK_HEADER_SIZE + NONCE_SIZE);
    SecureBuffer result(MK_SIZE);
    unsigned long long resultLen = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(result.data(), &resultLen, nullptr,
        reinterpret_cast<const unsigned char *>(encrypted.constData()), encrypted.size(),
        reinterpret_cast<const unsigned char *>(header.constData()), header.size(),
        reinterpret_cast<const unsigned char *>(nonce.constData()), kek.data());
    kek.clear();
    if (rc != 0 || resultLen != MK_SIZE || !result.lock()) { result.clear(); return false; }
    mk = std::move(result);
    return true;
}

bool Vault::setup(const SecureBuffer &pin)
{
    if (!isAvailable() || pin.empty() || isSetup()) return false;
    const QByteArray salt = generateRandom(SALT_SIZE);
    SecureBuffer kek = deriveKek(pin, salt, ARGON2_OPSLIMIT, ARGON2_MEMLIMIT);
    SecureBuffer master(MK_SIZE);
    if (kek.empty() || !master.lock()) return false;
    randombytes_buf(master.data(), MK_SIZE);
    const QByteArray emk = buildEmk(master, kek, salt);
    kek.clear();
    if (emk.isEmpty() || !backend_->store(emkKey_, emk)) return false;
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

QByteArray Vault::encrypt(const QByteArray &plain)
{
    if (!isUnlocked() || !sodiumReady()) return {};
    QByteArray header(MAGIC, MAGIC_SIZE);
    header.append(static_cast<char>(VERSION));
    header.append(static_cast<char>(DATA_RECORD));
    header.append(static_cast<char>(XCHACHA20_POLY1305));
    const QByteArray nonce = generateRandom(NONCE_SIZE);
    QByteArray encrypted(plain.size() + TAG_SIZE, Qt::Uninitialized);
    unsigned long long encryptedLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(reinterpret_cast<unsigned char *>(encrypted.data()), &encryptedLen,
            reinterpret_cast<const unsigned char *>(plain.constData()), plain.size(),
            reinterpret_cast<const unsigned char *>(header.constData()), header.size(), nullptr,
            reinterpret_cast<const unsigned char *>(nonce.constData()), mk_.data()) != 0) return {};
    encrypted.resize(static_cast<int>(encryptedLen));
    return header + nonce + encrypted;
}

SecureBuffer Vault::decryptToSecureBuffer(const QByteArray &cipher)
{
    if (!isUnlocked() || !sodiumReady() || cipher.size() < DATA_HEADER_SIZE + NONCE_SIZE + TAG_SIZE
        || !cipher.startsWith(QByteArray(MAGIC, MAGIC_SIZE)) || static_cast<quint8>(cipher[MAGIC_SIZE]) != VERSION
        || static_cast<quint8>(cipher[MAGIC_SIZE + 1]) != DATA_RECORD || static_cast<quint8>(cipher[MAGIC_SIZE + 2]) != XCHACHA20_POLY1305) return {};
    const QByteArray header = cipher.left(DATA_HEADER_SIZE);
    const QByteArray nonce = cipher.mid(DATA_HEADER_SIZE, NONCE_SIZE);
    const QByteArray encrypted = cipher.mid(DATA_HEADER_SIZE + NONCE_SIZE);
    SecureBuffer plain(static_cast<size_t>(encrypted.size() - TAG_SIZE));
    unsigned long long plainLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain.data(), &plainLen, nullptr,
            reinterpret_cast<const unsigned char *>(encrypted.constData()), encrypted.size(),
            reinterpret_cast<const unsigned char *>(header.constData()), header.size(),
            reinterpret_cast<const unsigned char *>(nonce.constData()), mk_.data()) != 0
        || !plain.resize(static_cast<size_t>(plainLen)) || !plain.lock()) { plain.clear(); return {}; }
    return plain;
}

QByteArray Vault::decrypt(const QByteArray &cipher)
{
    SecureBuffer plain = decryptToSecureBuffer(cipher);
    if (plain.empty()) return {};
    QByteArray result(reinterpret_cast<const char *>(plain.data()), static_cast<int>(plain.size()));
    plain.clear();
    return result;
}

bool Vault::changePin(const SecureBuffer &oldPin, const SecureBuffer &newPin)
{
    if (!isUnlocked() || newPin.empty()) return false;
    SecureBuffer verifiedMaster;
    if (!parseEmk(backend_->load(emkKey_), oldPin, verifiedMaster)) return false;
    const QByteArray salt = generateRandom(SALT_SIZE);
    SecureBuffer newKek = deriveKek(newPin, salt, ARGON2_OPSLIMIT, ARGON2_MEMLIMIT);
    const QByteArray newEmk = buildEmk(verifiedMaster, newKek, salt);
    verifiedMaster.clear();
    newKek.clear();
    return !newEmk.isEmpty() && backend_->store(emkKey_, newEmk);
}
