#include "Vault.h"

#include "ChaCha20.h"
#include "Kdf.h"
#include "Mac.h"
#include <QRandomGenerator>
#include <QtGlobal>
#include <algorithm>
#include <cstring>

Vault::Vault(ISecretStorageBackend *backend, const QString &emkKey)
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
    return backend_ && backend_->isAvailable();
}

bool Vault::isSetup() const
{
    return backend_ && !backend_->load(emkKey_).isEmpty();
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

SecureBuffer Vault::deriveKek(const SecureBuffer &pin, const QByteArray &salt) const
{
    Pbkdf2Sha256 kdf(100000);
    return kdf.derive(pin, salt, MK_SIZE);
}

QByteArray Vault::generateRandom(int length) const
{
    QByteArray out(length, 0);
    uint8_t *p = reinterpret_cast<uint8_t *>(out.data());
    int i = 0;
    while (i < length) {
        quint32 value = QRandomGenerator::system()->generate();
        int chunk = std::min(length - i, static_cast<int>(sizeof(quint32)));
        memcpy(p + i, &value, chunk);
        i += chunk;
    }
    return out;
}

QByteArray Vault::buildEmk(const SecureBuffer &mk, const SecureBuffer &kek, const QByteArray &salt, const QByteArray &nonce)
{
    QByteArray encryptedMk(MK_SIZE, 0);
    ChaCha20 chacha(
        reinterpret_cast<const uint8_t *>(kek.data()),
        reinterpret_cast<const uint8_t *>(nonce.constData())
    );
    chacha.crypt(
        reinterpret_cast<const uint8_t *>(mk.data()),
        reinterpret_cast<uint8_t *>(encryptedMk.data()),
        MK_SIZE
    );

    QByteArray blob;
    blob.reserve(1 + SALT_SIZE + NONCE_SIZE + encryptedMk.size() + TAG_SIZE);
    blob.append(static_cast<char>(VERSION));
    blob.append(salt);
    blob.append(nonce);
    blob.append(encryptedMk);

    HmacSha256 hmac;
    QByteArray tag = hmac.compute(kek, blob);
    blob.append(tag);

    return blob;
}

bool Vault::parseEmk(const QByteArray &emk, const SecureBuffer &kek, SecureBuffer &mk)
{
    const int expectedSize = 1 + SALT_SIZE + NONCE_SIZE + MK_SIZE + TAG_SIZE;
    if (emk.size() != expectedSize) {
        return false;
    }

    if (static_cast<uint8_t>(emk[0]) != VERSION) {
        return false;
    }

    QByteArray blob = emk.left(expectedSize - TAG_SIZE);
    QByteArray tag = emk.right(TAG_SIZE);

    HmacSha256 hmac;
    QByteArray expectedTag = hmac.compute(kek, blob);
    if (!std::equal(tag.begin(), tag.end(), expectedTag.begin())) {
        return false;
    }

    QByteArray salt = emk.mid(1, SALT_SIZE);
    QByteArray nonce = emk.mid(1 + SALT_SIZE, NONCE_SIZE);
    QByteArray encryptedMk = emk.mid(1 + SALT_SIZE + NONCE_SIZE, MK_SIZE);

    Q_UNUSED(salt)

    mk = SecureBuffer(MK_SIZE);
    ChaCha20 chacha(
        reinterpret_cast<const uint8_t *>(kek.data()),
        reinterpret_cast<const uint8_t *>(nonce.constData())
    );
    chacha.crypt(
        reinterpret_cast<const uint8_t *>(encryptedMk.constData()),
        mk.data(),
        MK_SIZE
    );

    return true;
}

bool Vault::setup(const SecureBuffer &pin)
{
    if (!isAvailable()) {
        return false;
    }

    QByteArray salt = generateRandom(SALT_SIZE);
    QByteArray nonce = generateRandom(NONCE_SIZE);

    SecureBuffer kek = deriveKek(pin, salt);

    mk_ = SecureBuffer(MK_SIZE);
    QByteArray randomMk = generateRandom(MK_SIZE);
    memcpy(mk_.data(), randomMk.constData(), MK_SIZE);
    randomMk.fill(0);

    QByteArray emk = buildEmk(mk_, kek, salt, nonce);

    kek.clear();

    if (!backend_->store(emkKey_, emk)) {
        lock();
        return false;
    }

    unlocked_ = true;
    return true;
}

bool Vault::unlock(const SecureBuffer &pin)
{
    if (!isAvailable()) {
        return false;
    }

    QByteArray emk = backend_->load(emkKey_);
    if (emk.isEmpty()) {
        return false;
    }

    if (emk.size() < 1 + SALT_SIZE + NONCE_SIZE) {
        return false;
    }

    QByteArray salt = emk.mid(1, SALT_SIZE);
    SecureBuffer kek = deriveKek(pin, salt);

    SecureBuffer mk;
    if (!parseEmk(emk, kek, mk)) {
        kek.clear();
        return false;
    }

    kek.clear();
    mk_ = std::move(mk);
    unlocked_ = true;
    return true;
}

QByteArray Vault::encrypt(const QByteArray &plain)
{
    if (!isUnlocked()) {
        return QByteArray();
    }
    return encryptWithMk(plain);
}

QByteArray Vault::decrypt(const QByteArray &cipher)
{
    if (!isUnlocked()) {
        return QByteArray();
    }
    QByteArray plain;
    if (!decryptWithMk(cipher, plain)) {
        return QByteArray();
    }
    return plain;
}

bool Vault::changePin(const SecureBuffer &oldPin, const SecureBuffer &newPin)
{
    if (!isUnlocked()) {
        return false;
    }

    QByteArray emk = backend_->load(emkKey_);
    if (emk.isEmpty()) {
        return false;
    }

    QByteArray salt = emk.mid(1, SALT_SIZE);
    SecureBuffer oldKek = deriveKek(oldPin, salt);

    SecureBuffer mk;
    if (!parseEmk(emk, oldKek, mk)) {
        oldKek.clear();
        return false;
    }
    oldKek.clear();

    QByteArray newSalt = generateRandom(SALT_SIZE);
    QByteArray newNonce = generateRandom(NONCE_SIZE);
    SecureBuffer newKek = deriveKek(newPin, newSalt);

    QByteArray newEmk = buildEmk(mk, newKek, newSalt, newNonce);
    newKek.clear();
    mk.clear();

    if (!backend_->store(emkKey_, newEmk)) {
        return false;
    }

    // メモリ上の MK は維持されたまま
    return true;
}

QByteArray Vault::encryptWithMk(const QByteArray &plain)
{
    QByteArray nonce = generateRandom(NONCE_SIZE);
    QByteArray cipher(plain.size(), 0);

    ChaCha20 chacha(
        reinterpret_cast<const uint8_t *>(mk_.data()),
        reinterpret_cast<const uint8_t *>(nonce.constData())
    );
    chacha.crypt(
        reinterpret_cast<const uint8_t *>(plain.constData()),
        reinterpret_cast<uint8_t *>(cipher.data()),
        static_cast<size_t>(plain.size())
    );

    QByteArray blob;
    blob.reserve(1 + NONCE_SIZE + cipher.size() + TAG_SIZE);
    blob.append(static_cast<char>(VERSION));
    blob.append(nonce);
    blob.append(cipher);

    HmacSha256 hmac;
    SecureBuffer mkCopy;
    mkCopy.assign(mk_.data(), mk_.size());
    QByteArray tag = hmac.compute(mkCopy, blob);
    mkCopy.clear();
    blob.append(tag);

    return blob;
}

bool Vault::decryptWithMk(const QByteArray &cipher, QByteArray &plain)
{
    const int minSize = 1 + NONCE_SIZE + TAG_SIZE;
    if (cipher.size() < minSize) {
        return false;
    }

    if (static_cast<uint8_t>(cipher[0]) != VERSION) {
        return false;
    }

    int payloadSize = cipher.size() - minSize;
    QByteArray blob = cipher.left(1 + NONCE_SIZE + payloadSize);
    QByteArray tag = cipher.right(TAG_SIZE);

    HmacSha256 hmac;
    SecureBuffer mkCopy;
    mkCopy.assign(mk_.data(), mk_.size());
    QByteArray expectedTag = hmac.compute(mkCopy, blob);
    mkCopy.clear();

    if (!std::equal(tag.begin(), tag.end(), expectedTag.begin())) {
        return false;
    }

    QByteArray nonce = cipher.mid(1, NONCE_SIZE);
    QByteArray encrypted = cipher.mid(1 + NONCE_SIZE, payloadSize);

    plain.resize(payloadSize);
    ChaCha20 chacha(
        reinterpret_cast<const uint8_t *>(mk_.data()),
        reinterpret_cast<const uint8_t *>(nonce.constData())
    );
    chacha.crypt(
        reinterpret_cast<const uint8_t *>(encrypted.constData()),
        reinterpret_cast<uint8_t *>(plain.data()),
        static_cast<size_t>(payloadSize)
    );

    return true;
}

