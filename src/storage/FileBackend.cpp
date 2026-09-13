#include "FileBackend.h"

#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QStandardPaths>
#include <QtGlobal>

#if defined(Q_OS_UNIX)
#include <sys/stat.h>
#endif

FileBackend::FileBackend(const QString &directory)
{
	if (directory.isEmpty()) {
		const QString configDir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
		directory_ = configDir + "/emk";
	} else {
		directory_ = directory;
	}
}

bool FileBackend::isAvailable() const
{
	return true;
}

QString FileBackend::name() const
{
	return "file";
}

QString FileBackend::sanitizeKey(const QString &key)
{
	// ファイル名として許可する文字は英数字、ドット、ハイフン、アンダースコアのみ
	QString safe;
	safe.reserve(key.size());
	for (const QChar &c : key) {
		const bool allowed = (c >= 'A' && c <= 'Z')
						 || (c >= 'a' && c <= 'z')
						 || (c >= '0' && c <= '9')
						 || c == '.'
						 || c == '_'
						 || c == '-';
		safe.append(allowed ? c : QChar('_'));
	}
	if (safe.isEmpty() || safe == QStringLiteral(".") || safe == QStringLiteral("..")) {
		safe = QStringLiteral("_key_");
	}
	if (safe.size() > 128) {
		safe = safe.left(128);
	}
	return safe;
}

static bool ensureDirectory(const QString &directory)
{
	QDir dir(directory);
	if (!dir.exists() && !dir.mkpath(".")) {
		return false;
	}
#if defined(Q_OS_UNIX)
	// 0700: 所有者のみアクセス可能
	const QByteArray encoded = directory.toUtf8();
	chmod(encoded.constData(), S_IRUSR | S_IWUSR | S_IXUSR);
#endif
	return true;
}

QString FileBackend::filePathForKey(const QString &key) const
{
	return directory_ + "/" + sanitizeKey(key);
}

bool FileBackend::store(const QString &key, const QByteArray &data)
{
	if (!ensureDirectory(directory_)) {
		return false;
	}

	const QString path = filePathForKey(key);

	QSaveFile file(path);
	if (!file.open(QIODevice::WriteOnly)) {
		return false;
	}
	file.write(data);
	if (!file.commit()) {
		return false;
	}

#if defined(Q_OS_UNIX)
	// 0600: 所有者のみ読み書き
	const QByteArray encoded = path.toUtf8();
	chmod(encoded.constData(), S_IRUSR | S_IWUSR);
#endif

	return true;
}

QByteArray FileBackend::load(const QString &key)
{
	const QString path = filePathForKey(key);
	QFile file(path);
	if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
		return QByteArray();
	}
	return file.readAll();
}

bool FileBackend::remove(const QString &key)
{
	const QString path = filePathForKey(key);
	return QFile::remove(path);
}
