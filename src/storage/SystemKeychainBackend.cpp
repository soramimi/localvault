#include "SystemKeychainBackend.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

#if defined(__linux__)
// Qt の signals マクロと glib の signals 構造体メンバー名が衝突するのを防ぐ
#undef signals
#include <libsecret/secret.h>

namespace {

std::string base64Encode(const Blob &data)
{
	static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string out;
	out.reserve(((data.size() + 2) / 3) * 4);
	for (size_t i = 0; i < data.size(); i += 3) {
		uint32_t triple = 0;
		int len = 0;
		for (size_t j = 0; j < 3 && i + j < data.size(); ++j) {
			triple |= static_cast<uint8_t>(data[i + j]) << (16 - j * 8);
			++len;
		}
		out.push_back(alphabet[(triple >> 18) & 0x3f]);
		out.push_back(alphabet[(triple >> 12) & 0x3f]);
		out.push_back(len > 1 ? alphabet[(triple >> 6) & 0x3f] : '=');
		out.push_back(len > 2 ? alphabet[triple & 0x3f] : '=');
	}
	return out;
}

Blob base64Decode(const std::string &in)
{
	static const int decodeTable[256] = {
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
		-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
		-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
	};

	Blob out;
	out.reserve((in.size() / 4) * 3);
	uint32_t triple = 0;
	int bits = 0;
	int pad = 0;
	for (char c : in) {
		if (std::isspace(static_cast<unsigned char>(c))) continue;
		if (c == '=') {
			++pad;
			continue;
		}
		int val = decodeTable[static_cast<unsigned char>(c)];
		if (val < 0) return { };
		triple = (triple << 6) | val;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push_back(static_cast<char>((triple >> bits) & 0xff));
		}
	}
	while (pad-- > 0 && !out.empty()) {
		// パディングは無視
	}
	return out;
}

} // namespace

class SystemKeychainBackend::Impl {
public:
	Impl()
	{
		schema_.name = "com.example.localvault.Vault";
		schema_.flags = SECRET_SCHEMA_NONE;
		schema_.attributes[0].name = "key";
		schema_.attributes[0].type = SECRET_SCHEMA_ATTRIBUTE_STRING;
		schema_.attributes[1].name = nullptr;
		schema_.attributes[1].type = SecretSchemaAttributeType(0);
	}

	bool isAvailable() const
	{
		GError *error = nullptr;
		gchar *password = secret_password_lookup_sync(
			&schema_,
			nullptr,
			&error,
			"key", "__availability_test__",
			nullptr);

		if (password) {
			secret_password_free(password);
		}

		bool available = true;
		if (error) {
			available = false;
			g_error_free(error);
		}
		return available;
	}

	bool store(const std::string &key, const Blob &data)
	{
		remove(key);

		std::string base64 = base64Encode(data);
		std::string label = "localvault vault: " + key;

		GError *error = nullptr;
		bool ok = secret_password_store_sync(
			&schema_,
			SECRET_COLLECTION_DEFAULT,
			label.c_str(),
			base64.c_str(),
			nullptr,
			&error,
			"key", key.c_str(),
			nullptr);

		if (error) {
			g_error_free(error);
		}
		return ok;
	}

	Blob load(const std::string &key)
	{
		GError *error = nullptr;
		gchar *password = secret_password_lookup_sync(
			&schema_,
			nullptr,
			&error,
			"key", key.c_str(),
			nullptr);

		Blob result;
		if (password) {
			result = base64Decode(password);
			secret_password_free(password);
		}

		if (error) {
			g_error_free(error);
		}
		return result;
	}

	bool remove(const std::string &key)
	{
		GError *error = nullptr;
		bool ok = secret_password_clear_sync(
			&schema_,
			nullptr,
			&error,
			"key", key.c_str(),
			nullptr);

		if (error) {
			g_error_free(error);
		}
		return ok;
	}

private:
	SecretSchema schema_;
};

#elif defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

class SystemKeychainBackend::Impl {
public:
	bool isAvailable() const
	{
		return true;
	}

	bool store(const std::string &key, const Blob &data)
	{
		remove(key);

		CFStringRef service = CFStringCreateWithCString(nullptr, serviceName_.c_str(), kCFStringEncodingUTF8);
		CFStringRef account = CFStringCreateWithCString(nullptr, key.c_str(), kCFStringEncodingUTF8);
		CFDataRef value = CFDataCreate(nullptr, reinterpret_cast<const UInt8 *>(data.data()), static_cast<CFIndex>(data.size()));

		const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData, kSecAttrAccessible };
		const void *values[] = { kSecClassGenericPassword, service, account, value, kSecAttrAccessibleWhenUnlockedThisDeviceOnly };
		CFDictionaryRef query = CFDictionaryCreate(nullptr, keys, values, 5, nullptr, nullptr);

		OSStatus status = SecItemAdd(query, nullptr);

		CFRelease(query);
		CFRelease(value);
		CFRelease(account);
		CFRelease(service);

		return status == errSecSuccess;
	}

	Blob load(const std::string &key)
	{
		CFStringRef service = CFStringCreateWithCString(nullptr, serviceName_.c_str(), kCFStringEncodingUTF8);
		CFStringRef account = CFStringCreateWithCString(nullptr, key.c_str(), kCFStringEncodingUTF8);

		const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit };
		const void *values[] = { kSecClassGenericPassword, service, account, kCFBooleanTrue, kSecMatchLimitOne };
		CFDictionaryRef query = CFDictionaryCreate(nullptr, keys, values, 5, nullptr, nullptr);

		CFDataRef result = nullptr;
		OSStatus status = SecItemCopyMatching(query, reinterpret_cast<CFTypeRef *>(&result));

		Blob data;
		if (status == errSecSuccess && result) {
			data.resize(static_cast<size_t>(CFDataGetLength(result)));
			std::memcpy(data.data(), CFDataGetBytePtr(result), data.size());
			CFRelease(result);
		}

		CFRelease(query);
		CFRelease(account);
		CFRelease(service);

		return data;
	}

	bool remove(const std::string &key)
	{
		CFStringRef service = CFStringCreateWithCString(nullptr, serviceName_.c_str(), kCFStringEncodingUTF8);
		CFStringRef account = CFStringCreateWithCString(nullptr, key.c_str(), kCFStringEncodingUTF8);

		const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
		const void *values[] = { kSecClassGenericPassword, service, account };
		CFDictionaryRef query = CFDictionaryCreate(nullptr, keys, values, 3, nullptr, nullptr);

		OSStatus status = SecItemDelete(query);

		CFRelease(query);
		CFRelease(account);
		CFRelease(service);

		return status == errSecSuccess || status == errSecItemNotFound;
	}

private:
	std::string serviceName_ = "localvault-vault";
};

#elif defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <dpapi.h>
#include <shlobj.h>
#include <windows.h>

namespace {

std::filesystem::path windowsAppDataPath()
{
	wchar_t *path = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path)) && path) {
		std::filesystem::path result(path);
		CoTaskMemFree(path);
		return result;
	}
	const char *appdata = std::getenv("APPDATA");
	if (appdata) {
		return std::filesystem::path(appdata);
	}
	return std::filesystem::path(std::getenv("USERPROFILE") ? std::getenv("USERPROFILE") : ".");
}

std::string generateTempSuffix()
{
	std::random_device rd;
	std::uniform_int_distribution<uint32_t> dist;
	std::ostringstream oss;
	oss << ".tmp" << std::hex << dist(rd);
	return oss.str();
}

std::string sanitizeKey(const std::string &key)
{
	std::string safe = key;
	for (char &c : safe) {
		if (c == '/' || c == '\\' || c == ':') {
			c = '_';
		}
	}
	return safe;
}

} // namespace

class SystemKeychainBackend::Impl {
public:
	Impl()
	{
		directory_ = windowsAppDataPath() / "localvault" / "emk";
	}

	bool isAvailable() const
	{
		return true;
	}

	bool store(const std::string &key, const Blob &data)
	{
		DATA_BLOB in;
		in.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(data.data()));
		in.cbData = static_cast<DWORD>(data.size());

		DATA_BLOB out;
		if (!CryptProtectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
			return false;
		}

		Blob encrypted(reinterpret_cast<char *>(out.pbData), reinterpret_cast<char *>(out.pbData) + out.cbData);
		LocalFree(out.pbData);

		try {
			std::filesystem::create_directories(directory_);
		} catch (...) {
			return false;
		}

		const std::filesystem::path path = directory_ / sanitizeKey(key);
		const std::filesystem::path tempPath = path.string() + generateTempSuffix();

		{
			std::ofstream file(tempPath, std::ios::binary | std::ios::trunc);
			if (!file) {
				std::error_code ec;
				std::filesystem::remove(tempPath, ec);
				return false;
			}
			if (!encrypted.empty()) {
				file.write(encrypted.data(), static_cast<std::streamsize>(encrypted.size()));
			}
			if (!file) {
				std::error_code ec;
				std::filesystem::remove(tempPath, ec);
				return false;
			}
			file.flush();
		}

		std::error_code ec;
		std::filesystem::rename(tempPath, path, ec);
		if (ec) {
			std::error_code removeEc;
			std::filesystem::remove(tempPath, removeEc);
			return false;
		}
		return true;
	}

	Blob load(const std::string &key)
	{
		const std::filesystem::path path = directory_ / sanitizeKey(key);
		if (!std::filesystem::is_regular_file(path)) {
			return { };
		}

		std::ifstream file(path, std::ios::binary | std::ios::ate);
		if (!file) {
			return { };
		}
		const auto size = file.tellg();
		if (size < 0) {
			return { };
		}
		file.seekg(0, std::ios::beg);

		Blob encrypted(static_cast<size_t>(size));
		if (size > 0 && !file.read(encrypted.data(), size)) {
			return { };
		}

		DATA_BLOB in;
		in.pbData = reinterpret_cast<BYTE *>(encrypted.data());
		in.cbData = static_cast<DWORD>(encrypted.size());

		DATA_BLOB out;
		if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
			return { };
		}

		Blob data(reinterpret_cast<char *>(out.pbData), reinterpret_cast<char *>(out.pbData) + out.cbData);
		LocalFree(out.pbData);
		return data;
	}

	bool remove(const std::string &key)
	{
		const std::filesystem::path path = directory_ / sanitizeKey(key);
		std::error_code ec;
		return std::filesystem::remove(path, ec);
	}

private:
	std::filesystem::path directory_;
};

#else
class SystemKeychainBackend::Impl {
public:
	bool isAvailable() const
	{
		return false;
	}

	bool store(const std::string &, const Blob &)
	{
		return false;
	}

	Blob load(const std::string &)
	{
		return { };
	}

	bool remove(const std::string &)
	{
		return false;
	}
};
#endif

SystemKeychainBackend::SystemKeychainBackend()
	: impl_(new Impl())
{
}

SystemKeychainBackend::~SystemKeychainBackend()
{
	delete impl_;
}

bool SystemKeychainBackend::isAvailable() const
{
	return impl_->isAvailable();
}

std::string SystemKeychainBackend::name() const
{
#if defined(__linux__)
	return "system-keychain-libsecret";
#elif defined(__APPLE__)
	return "system-keychain-macos";
#elif defined(_WIN32)
	return "system-keychain-dpapi";
#else
	return "system-keychain-unavailable";
#endif
}

bool SystemKeychainBackend::store(const std::string &key, const Blob &data)
{
	return impl_->store(key, data);
}

Blob SystemKeychainBackend::load(const std::string &key)
{
	return impl_->load(key);
}

bool SystemKeychainBackend::remove(const std::string &key)
{
	return impl_->remove(key);
}
