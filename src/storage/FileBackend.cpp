#include "FileBackend.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
#include <shlobj.h>
#include <windows.h>
#endif

namespace {

std::string generateTempSuffix()
{
	std::random_device rd;
	std::uniform_int_distribution<uint32_t> dist;
	std::ostringstream oss;
	oss << ".tmp" << std::hex << dist(rd);
	return oss.str();
}

#if defined(__unix__) || defined(__APPLE__)
bool setUnixPermissions(const std::filesystem::path &path, mode_t mode)
{
	return chmod(path.c_str(), mode) == 0;
}
#endif

} // namespace

FileBackend::FileBackend(const std::filesystem::path &directory)
{
	if (directory.empty()) {
		directory_ = defaultConfigDirectory() / "emk";
	} else {
		directory_ = directory;
	}
}

bool FileBackend::isAvailable() const
{
	return true;
}

std::string FileBackend::name() const
{
	return "file";
}

std::string FileBackend::sanitizeKey(const std::string &key)
{
	// ファイル名として許可する文字は英数字、ドット、ハイフン、アンダースコアのみ
	std::string safe;
	safe.reserve(key.size());
	for (const char c : key) {
		const bool allowed = (c >= 'A' && c <= 'Z')
			|| (c >= 'a' && c <= 'z')
			|| (c >= '0' && c <= '9')
			|| c == '.'
			|| c == '_'
			|| c == '-';
		safe.push_back(allowed ? c : '_');
	}
	if (safe.empty() || safe == "." || safe == "..") {
		safe = "_key_";
	}
	if (safe.size() > 128) {
		safe.resize(128);
	}
	return safe;
}

std::filesystem::path FileBackend::defaultConfigDirectory()
{
#if defined(_WIN32)
	wchar_t *path = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path)) && path) {
		std::filesystem::path result(path);
		CoTaskMemFree(path);
		return result / "localvault";
	}
	const char *appdata = std::getenv("APPDATA");
	if (appdata) {
		return std::filesystem::path(appdata) / "localvault";
	}
	return std::filesystem::path(std::getenv("USERPROFILE") ? std::getenv("USERPROFILE") : ".") / "localvault";
#elif defined(__APPLE__)
	const char *home = std::getenv("HOME");
	if (home) {
		return std::filesystem::path(home) / "Library" / "Application Support" / "localvault";
	}
	return std::filesystem::path(".") / "localvault";
#else
	const char *xdgConfigHome = std::getenv("XDG_CONFIG_HOME");
	if (xdgConfigHome) {
		return std::filesystem::path(xdgConfigHome) / "localvault";
	}
	const char *home = std::getenv("HOME");
	if (home) {
		return std::filesystem::path(home) / ".config" / "localvault";
	}
	return std::filesystem::path(".") / "localvault";
#endif
}

std::filesystem::path FileBackend::filePathForKey(const std::string &key) const
{
	return directory_ / sanitizeKey(key);
}

static bool ensureDirectory(const std::filesystem::path &directory)
{
	try {
		std::filesystem::create_directories(directory);
	} catch (...) {
		return false;
	}
#if defined(__unix__) || defined(__APPLE__)
	setUnixPermissions(directory, S_IRUSR | S_IWUSR | S_IXUSR);
#endif
	return std::filesystem::is_directory(directory);
}

bool FileBackend::store(const std::string &key, const Blob &data)
{
	if (!ensureDirectory(directory_)) {
		return false;
	}

	const std::filesystem::path path = filePathForKey(key);
	const std::filesystem::path tempPath = path.string() + generateTempSuffix();

	{
		std::ofstream file(tempPath, std::ios::binary | std::ios::trunc);
		if (!file) {
			std::error_code ec;
			std::filesystem::remove(tempPath, ec);
			return false;
		}
		if (!data.empty()) {
			file.write(data.data(), static_cast<std::streamsize>(data.size()));
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

#if defined(__unix__) || defined(__APPLE__)
	setUnixPermissions(path, S_IRUSR | S_IWUSR);
#endif

	return true;
}

Blob FileBackend::load(const std::string &key)
{
	const std::filesystem::path path = filePathForKey(key);
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

	Blob data(static_cast<size_t>(size));
	if (size > 0 && !file.read(data.data(), size)) {
		return { };
	}
	return data;
}

bool FileBackend::remove(const std::string &key)
{
	const std::filesystem::path path = filePathForKey(key);
	std::error_code ec;
	return std::filesystem::remove(path, ec);
}
