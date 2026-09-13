#include <QApplication>
#include <QByteArray>
#include <QCryptographicHash>
#include <QDir>
#include <QMessageBox>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <cstdio>
#include <cstring>
#include <memory>

#include "gui/PinDialog.h"
#include "storage/FileBackend.h"
#include "storage/SystemKeychainBackend.h"
#include "vault/ChaCha20.h"
#include "vault/Kdf.h"
#include "vault/Mac.h"
#include "vault/SecureBuffer.h"
#include "vault/Vault.h"

// ===== Test harness =====

static int tests_run = 0;
static int tests_passed = 0;

static void check(bool condition, const char *name)
{
    tests_run++;
    if (condition) {
        tests_passed++;
        std::printf("PASS: %s\n", name);
    } else {
        std::printf("FAIL: %s\n", name);
    }
}

static QByteArray toHex(const SecureBuffer &buf)
{
    return QByteArray(reinterpret_cast<const char *>(buf.data()), static_cast<int>(buf.size())).toHex();
}

static SecureBuffer pinFromUtf8(const char *s)
{
    SecureBuffer pin;
    pin.assign(s, strlen(s));
    return pin;
}

static void testSecureBuffer()
{
    SecureBuffer buf(32);
    check(buf.size() == 32, "SecureBuffer size");

    std::fill(buf.begin(), buf.end(), 0xab);
    buf.clear();
    bool allZero = std::all_of(buf.begin(), buf.end(), [](uint8_t v) { return v == 0; });
    check(allZero, "SecureBuffer clear zeros memory");
    check(buf.empty(), "SecureBuffer empty after clear");
}

static void testSha256()
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData("abc");
    QByteArray result = hash.result();
    QByteArray expected = QByteArray::fromHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check(result == expected, "SHA256 abc vector");
}

static void testChaCha20()
{
    uint8_t key[ChaCha20::KEY_SIZE] = {};
    uint8_t nonce[ChaCha20::NONCE_SIZE] = {};
    for (int i = 0; i < ChaCha20::KEY_SIZE; i++) key[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < ChaCha20::NONCE_SIZE; i++) nonce[i] = static_cast<uint8_t>(i + 0x10);

    const char *plaintext = "Hello, ChaCha20 World! This is a test message.";
    size_t len = strlen(plaintext);

    QByteArray encrypted(len, 0);
    QByteArray decrypted(len, 0);

    ChaCha20 enc(key, nonce);
    enc.crypt(reinterpret_cast<const uint8_t *>(plaintext), reinterpret_cast<uint8_t *>(encrypted.data()), len);

    check(encrypted != QByteArray(plaintext, static_cast<int>(len)), "ChaCha20 encryption changes data");

    ChaCha20 dec(key, nonce);
    dec.crypt(reinterpret_cast<const uint8_t *>(encrypted.constData()), reinterpret_cast<uint8_t *>(decrypted.data()), len);

    check(decrypted == QByteArray(plaintext, static_cast<int>(len)), "ChaCha20 roundtrip");
}

static void testHmacSha256()
{
    HmacSha256 hmac;

    SecureBuffer key(20);
    std::fill(key.begin(), key.end(), 0x0b);
    check(hmac.compute(key, "Hi There") ==
              QByteArray::fromHex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
          "HMAC-SHA256 RFC 4231 vector");

    SecureBuffer key2;
    key2.assign("key", 3);
    check(hmac.compute(key2, "The quick brown fox jumps over the lazy dog") ==
              QByteArray::fromHex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"),
          "HMAC-SHA256 string key vector");
}

static void testPbkdf2Sha256()
{
    SecureBuffer password;
    password.assign("password", 8);
    Pbkdf2Sha256 kdf(1);
    SecureBuffer derived = kdf.derive(password, "salt", 32);
    QByteArray expected = QByteArray::fromHex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    check(toHex(derived) == expected.toHex(), "PBKDF2-SHA256 RFC 7914 vector");
}

static void testVaultSetupUnlock()
{
    QTemporaryDir tempDir;
    check(tempDir.isValid(), "Vault temp dir valid");

    FileBackend backend(tempDir.path());
    Vault vault(&backend);

    check(vault.isAvailable(), "Vault backend available");
    check(!vault.isSetup(), "Vault not setup initially");
    check(!vault.isUnlocked(), "Vault not unlocked initially");

    SecureBuffer pin = pinFromUtf8("1234");
    check(vault.setup(pin), "Vault setup");
    check(vault.isSetup(), "Vault is setup after setup");
    check(vault.isUnlocked(), "Vault is unlocked after setup");

    QByteArray secret = "API_KEY=sk-1234567890abcdef";
    QByteArray encrypted = vault.encrypt(secret);
    check(!encrypted.isEmpty(), "Vault encrypt");
    check(encrypted != secret, "Vault encryption changes data");

    QByteArray decrypted = vault.decrypt(encrypted);
    check(decrypted == secret, "Vault decrypt");

    vault.lock();
    check(!vault.isUnlocked(), "Vault locked");
    check(vault.decrypt(encrypted).isEmpty(), "Vault decrypt fails when locked");

    check(vault.unlock(pin), "Vault unlock");
    check(vault.isUnlocked(), "Vault unlocked");
    check(vault.decrypt(encrypted) == secret, "Vault decrypt after unlock");
}

static void testVaultWrongPin()
{
    QTemporaryDir tempDir;
    FileBackend backend(tempDir.path());
    Vault vault(&backend);

    SecureBuffer pin = pinFromUtf8("correct");
    check(vault.setup(pin), "Vault setup for wrong PIN test");

    SecureBuffer wrongPin = pinFromUtf8("wrong");
    check(!vault.unlock(wrongPin), "Vault unlock with wrong PIN fails");
}

static void testVaultChangePin()
{
    QTemporaryDir tempDir;
    FileBackend backend(tempDir.path());
    Vault vault(&backend);

    SecureBuffer oldPin = pinFromUtf8("oldpin");
    SecureBuffer newPin = pinFromUtf8("newpin");

    check(vault.setup(oldPin), "Vault setup for PIN change");

    QByteArray secret = "SuperSecretToken";
    QByteArray encrypted = vault.encrypt(secret);

    check(vault.changePin(oldPin, newPin), "Vault change PIN");
    check(vault.isUnlocked(), "Vault still unlocked after PIN change");

    vault.lock();
    check(!vault.unlock(oldPin), "Vault unlock with old PIN fails");
    check(vault.unlock(newPin), "Vault unlock with new PIN succeeds");
    check(vault.decrypt(encrypted) == secret, "Vault decrypt after PIN change");
}

static void testVaultTamperedData()
{
    QTemporaryDir tempDir;
    FileBackend backend(tempDir.path());
    Vault vault(&backend);

    SecureBuffer pin = pinFromUtf8("1234");
    check(vault.setup(pin), "Vault setup for tamper test");

    QByteArray secret = "TamperTestSecret";
    QByteArray encrypted = vault.encrypt(secret);

    char tampered = static_cast<char>(encrypted[encrypted.size() / 2] ^ 0xff);
    encrypted[encrypted.size() / 2] = tampered;

    check(vault.decrypt(encrypted).isEmpty(), "Vault detects tampered data");
}

static void testSystemKeychainBackend()
{
    SystemKeychainBackend backend;
    if (!backend.isAvailable()) {
        std::printf("SKIP: SystemKeychainBackend not available\n");
        return;
    }

    const QString testKey = QStringLiteral("obfuscation-phase3-test");
    QByteArray data = "EMK blob for system keychain test";

    check(backend.store(testKey, data), "SystemKeychainBackend store");
    QByteArray loaded = backend.load(testKey);
    check(loaded == data, "SystemKeychainBackend load");
    check(backend.remove(testKey), "SystemKeychainBackend remove");
    check(backend.load(testKey).isEmpty(), "SystemKeychainBackend removed");
}

static void testVaultWithSystemKeychain()
{
    SystemKeychainBackend backend;
    if (!backend.isAvailable()) {
        std::printf("SKIP: SystemKeychainBackend not available for Vault test\n");
        return;
    }

    const QString testKey = QStringLiteral("obfuscation-phase3-vault-test");
    backend.remove(testKey);

    Vault vault(&backend, testKey);
    SecureBuffer pin = pinFromUtf8("phase3pin");

    check(vault.setup(pin), "Vault setup with SystemKeychainBackend");

    QByteArray secret = "Secret stored via system keychain";
    QByteArray encrypted = vault.encrypt(secret);
    check(!encrypted.isEmpty(), "Vault encrypt with SystemKeychainBackend");

    vault.lock();
    check(vault.unlock(pin), "Vault unlock with SystemKeychainBackend");
    check(vault.decrypt(encrypted) == secret, "Vault decrypt with SystemKeychainBackend");

    vault.lock();
    backend.remove(testKey);
}

static int runTests()
{
    std::printf("=== Phase 1: Cryptographic Primitives Tests ===\n");
    testSecureBuffer();
    testSha256();
    testChaCha20();
    testHmacSha256();
    testPbkdf2Sha256();

    std::printf("\n=== Phase 2: Vault Core Tests ===\n");
    testVaultSetupUnlock();
    testVaultWrongPin();
    testVaultChangePin();
    testVaultTamperedData();

    std::printf("\n=== Phase 3: System Keychain Backend Tests ===\n");
    testSystemKeychainBackend();
    testVaultWithSystemKeychain();

    std::printf("\nResults: %d / %d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}

// ===== GUI demo =====

static std::unique_ptr<ISecretStorageBackend> createBackend()
{
    auto systemBackend = std::make_unique<SystemKeychainBackend>();
    if (systemBackend->isAvailable()) {
        return systemBackend;
    }

    const QString configDir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    return std::make_unique<FileBackend>(configDir + "/emk");
}

static int runGuiDemo(int argc, char *argv[])
{
    QApplication app(argc, argv);

    auto backend = createBackend();
    Vault vault(backend.get(), QStringLiteral("vault_emk"));

    if (!vault.isSetup()) {
        bool ok = false;
        SecureBuffer pin = PinDialog::setupPin(nullptr, &ok);
        if (!ok || pin.empty()) {
            QMessageBox::information(nullptr, QObject::tr("Cancelled"), QObject::tr("Vault setup was cancelled."));
            return 0;
        }

        if (!vault.setup(pin)) {
            QMessageBox::critical(nullptr, QObject::tr("Error"), QObject::tr("Failed to set up Vault."));
            pin.clear();
            return 1;
        }
        pin.clear();

        QMessageBox::information(nullptr, QObject::tr("Vault Setup"), QObject::tr("Vault has been set up successfully."));
    }

    bool ok = false;
    SecureBuffer pin = PinDialog::requestPin(nullptr, &ok);
    if (!ok || pin.empty()) {
        return 0;
    }

    if (!vault.unlock(pin)) {
        QMessageBox::critical(nullptr, QObject::tr("Unlock Failed"), QObject::tr("Incorrect PIN or corrupted Vault data."));
        pin.clear();
        return 1;
    }
    pin.clear();

    QByteArray secret = "API_KEY=sk-abcdef1234567890";
    QByteArray encrypted = vault.encrypt(secret);
    QByteArray decrypted = vault.decrypt(encrypted);

    QString message;
    if (decrypted == secret) {
        message = QObject::tr("Vault unlocked and roundtrip verified successfully.\n\nDecrypted: %1")
                      .arg(QString::fromUtf8(decrypted));
    } else {
        message = QObject::tr("Vault roundtrip failed.");
    }

    QMessageBox::information(nullptr, QObject::tr("Vault Demo"), message);

    vault.lock();
    return 0;
}

// ===== Entry point =====

int main(int argc, char *argv[])
{
    if (argc > 1 && QString::fromLatin1(argv[1]) == QStringLiteral("--test")) {
        return runTests();
    }

    return runGuiDemo(argc, argv);
}
