#include <QApplication>
#include <QByteArray>
#include <QCoreApplication>
#include <QMessageBox>
#include <QPushButton>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>

#include "gui/PinDialog.h"
#include "storage/FileBackend.h"
#include "storage/SystemKeychainBackend.h"
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
	check(buf.lock(), "SecureBuffer locks memory");
	check(!buf.resize(64), "SecureBuffer rejects resize while locked");
	buf.clear();
	check(buf.empty(), "SecureBuffer empty after clear");
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
	
	SecureBuffer secureDecrypted = vault.decryptToSecureBuffer(encrypted);
	check(secureDecrypted.size() == static_cast<size_t>(secret.size())
			  && QByteArray(reinterpret_cast<const char *>(secureDecrypted.data()), static_cast<int>(secureDecrypted.size())) == secret,
		  "Vault decrypts to SecureBuffer");
	
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
	check(!vault.setup(pin), "Vault refuses to overwrite existing setup");
	
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

static void testVaultReset()
{
	QTemporaryDir tempDir;
	FileBackend backend(tempDir.path());
	Vault vault(&backend);
	
	SecureBuffer oldPin = pinFromUtf8("oldpin");
	SecureBuffer newPin = pinFromUtf8("newpin");
	check(vault.setup(oldPin), "Vault setup for reset");
	QByteArray oldCipher = vault.encrypt("OldSecret");
	
	check(vault.reset(newPin), "Vault reset");
	check(vault.isUnlocked(), "Vault unlocked after reset");
	check(vault.decrypt(oldCipher).isEmpty(), "Vault cannot decrypt pre-reset data");
	
	vault.lock();
	check(!vault.unlock(oldPin), "Vault old PIN fails after reset");
	check(vault.unlock(newPin), "Vault new PIN succeeds after reset");
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
	
	const QString testKey = QStringLiteral("localvault-phase3-test");
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
	
	const QString testKey = QStringLiteral("localvault-phase3-vault-test");
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
	std::printf("=== Secure Memory Tests ===\n");
	testSecureBuffer();
	
	std::printf("\n=== Phase 2: Vault Core Tests ===\n");
	testVaultSetupUnlock();
	testVaultWrongPin();
	testVaultChangePin();
	testVaultReset();
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

static int runCliReset()
{
	auto backend = createBackend();
	Vault vault(backend.get());
	if (!vault.isAvailable()) {
		std::fprintf(stderr, "ERROR: No Vault storage backend is available.\n");
		return 1;
	}
	if (!vault.isSetup()) {
		std::printf("No existing Vault was found.\n");
		return 0;
	}
	if (!backend->remove(vault.emkKey())) {
		std::fprintf(stderr, "ERROR: Failed to remove the existing Vault.\n");
		return 1;
	}
	std::printf("Vault removed. Run the application normally to set up a new Vault.\n");
	return 0;
}

static bool resetVaultFromGui(Vault &vault)
{
	const auto confirmation = QMessageBox::warning(
		nullptr, QObject::tr("Reset Vault"),
		QObject::tr("This permanently deletes the current Vault. Data encrypted with its current key cannot be recovered.\n\nContinue?"),
		QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
	
	if (confirmation != QMessageBox::Yes) return false;
	
	bool ok = false;
	SecureBuffer newPin = PinDialog::setupPin(nullptr, &ok);
	if (!ok || newPin.empty()) return false;
	const bool reset = vault.reset(newPin);
	newPin.clear();
	if (!reset) {
		QMessageBox::critical(nullptr, QObject::tr("Reset Failed"), QObject::tr("Failed to reset the Vault."));
	}
	return reset;
}

static int runGuiDemo(int argc, char *argv[])
{
	QApplication app(argc, argv);
	
	auto backend = createBackend();
	Vault vault(backend.get());
	
	if (vault.isSetup()) {
		for (;;) {
			QMessageBox choice;
			choice.setWindowTitle(QObject::tr("Vault"));
			choice.setText(QObject::tr("Unlock the existing Vault, or permanently reset it?"));
			QPushButton *unlockButton = choice.addButton(QObject::tr("Unlock"), QMessageBox::AcceptRole);
			QPushButton *resetButton = choice.addButton(QObject::tr("Reset Vault"), QMessageBox::DestructiveRole);
			choice.addButton(QMessageBox::Cancel);
			choice.exec();
			
			if (choice.clickedButton() == unlockButton) break;
			if (choice.clickedButton() == resetButton) {
				if (resetVaultFromGui(vault)) break;
				continue;
			}
			return 0;
		}
	} else {
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
	
	if (!vault.isUnlocked()) {
		bool ok = false;
		SecureBuffer pin = PinDialog::requestPin(nullptr, &ok);
		if (!ok || pin.empty()) return 0;
		if (!vault.unlock(pin)) {
			QMessageBox::critical(nullptr, QObject::tr("Unlock Failed"), QObject::tr("Incorrect PIN or corrupted Vault data."));
			pin.clear();
			return 1;
		}
		pin.clear();
	}
	
	QByteArray secret = "API_KEY=sk-abcdef1234567890";
	QByteArray encrypted = vault.encrypt(secret);
	QByteArray decrypted = vault.decrypt(encrypted);
	
	QString message;
	if (decrypted == secret) {
		message = QObject::tr("Vault unlocked and roundtrip verified successfully.\n\nDecrypted: %1").arg(QString::fromUtf8(decrypted));
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
	
	if (argc > 1 && QString::fromLatin1(argv[1]) == QStringLiteral("--reset")) {
		if (argc < 3 || QString::fromLatin1(argv[2]) != QStringLiteral("--yes")) {
			std::fprintf(stderr, "Refusing to reset without --yes. Usage: %s --reset --yes\n", argv[0]);
			return 2;
		}
		QCoreApplication app(argc, argv);
		return runCliReset();
	}
	
	return runGuiDemo(argc, argv);
}
