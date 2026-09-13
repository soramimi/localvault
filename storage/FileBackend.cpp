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

QString FileBackend::directory() const
{
    return directory_;
}

QString FileBackend::sanitizeKey(const QString &key)
{
    // ファイル名として安全でない文字を置換
    QString safe = key;
    safe.replace('/', '_');
    safe.replace('\\', '_');
    safe.replace(':', '_');
    return safe;
}

QString FileBackend::filePathForKey(const QString &key) const
{
    return directory_ + "/" + sanitizeKey(key);
}

bool FileBackend::store(const QString &key, const QByteArray &data)
{
    QDir dir(directory_);
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            return false;
        }
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
