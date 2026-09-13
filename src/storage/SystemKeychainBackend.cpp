#include "SystemKeychainBackend.h"

#include <QString>
#include <QtGlobal>

#if defined(Q_OS_LINUX)
// Qt の signals マクロと glib の signals 構造体メンバー名が衝突するのを防ぐ
#undef signals
#include <libsecret/secret.h>

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

    bool store(const QString &key, const QByteArray &data)
    {
        remove(key);

        QByteArray base64 = data.toBase64();
        QByteArray label = QStringLiteral("localvault vault: %1").arg(key).toUtf8();
        QByteArray keyUtf8 = key.toUtf8();

        GError *error = nullptr;
        bool ok = secret_password_store_sync(
            &schema_,
            SECRET_COLLECTION_DEFAULT,
            label.constData(),
            base64.constData(),
            nullptr,
            &error,
            "key", keyUtf8.constData(),
            nullptr);

        if (error) {
            g_error_free(error);
        }
        return ok;
    }

    QByteArray load(const QString &key)
    {
        QByteArray keyUtf8 = key.toUtf8();
        GError *error = nullptr;
        gchar *password = secret_password_lookup_sync(
            &schema_,
            nullptr,
            &error,
            "key", keyUtf8.constData(),
            nullptr);

        QByteArray result;
        if (password) {
            result = QByteArray::fromBase64(password);
            secret_password_free(password);
        }

        if (error) {
            g_error_free(error);
        }
        return result;
    }

    bool remove(const QString &key)
    {
        QByteArray keyUtf8 = key.toUtf8();
        GError *error = nullptr;
        bool ok = secret_password_clear_sync(
            &schema_,
            nullptr,
            &error,
            "key", keyUtf8.constData(),
            nullptr);

        if (error) {
            g_error_free(error);
        }
        return ok;
    }

private:
    SecretSchema schema_;
};

#elif defined(Q_OS_MACOS)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

class SystemKeychainBackend::Impl {
public:
    bool isAvailable() const
    {
        return true;
    }

    bool store(const QString &key, const QByteArray &data)
    {
        remove(key);

        QByteArray serviceUtf8 = serviceName_.toUtf8();
        QByteArray keyUtf8 = key.toUtf8();

        CFStringRef service = CFStringCreateWithCString(nullptr, serviceUtf8.constData(), kCFStringEncodingUTF8);
        CFStringRef account = CFStringCreateWithCString(nullptr, keyUtf8.constData(), kCFStringEncodingUTF8);
        CFDataRef value = CFDataCreate(nullptr, reinterpret_cast<const UInt8 *>(data.constData()), data.size());

        const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData };
        const void *values[] = { kSecClassGenericPassword, service, account, value };
        CFDictionaryRef query = CFDictionaryCreate(nullptr, keys, values, 4, nullptr, nullptr);

        OSStatus status = SecItemAdd(query, nullptr);

        CFRelease(query);
        CFRelease(value);
        CFRelease(account);
        CFRelease(service);

        return status == errSecSuccess;
    }

    QByteArray load(const QString &key)
    {
        QByteArray serviceUtf8 = serviceName_.toUtf8();
        QByteArray keyUtf8 = key.toUtf8();

        CFStringRef service = CFStringCreateWithCString(nullptr, serviceUtf8.constData(), kCFStringEncodingUTF8);
        CFStringRef account = CFStringCreateWithCString(nullptr, keyUtf8.constData(), kCFStringEncodingUTF8);

        const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit };
        const void *values[] = { kSecClassGenericPassword, service, account, kCFBooleanTrue, kSecMatchLimitOne };
        CFDictionaryRef query = CFDictionaryCreate(nullptr, keys, values, 5, nullptr, nullptr);

        CFDataRef result = nullptr;
        OSStatus status = SecItemCopyMatching(query, reinterpret_cast<CFTypeRef *>(&result));

        QByteArray data;
        if (status == errSecSuccess && result) {
            data = QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(result)), CFDataGetLength(result));
            CFRelease(result);
        }

        CFRelease(query);
        CFRelease(account);
        CFRelease(service);

        return data;
    }

    bool remove(const QString &key)
    {
        QByteArray serviceUtf8 = serviceName_.toUtf8();
        QByteArray keyUtf8 = key.toUtf8();

        CFStringRef service = CFStringCreateWithCString(nullptr, serviceUtf8.constData(), kCFStringEncodingUTF8);
        CFStringRef account = CFStringCreateWithCString(nullptr, keyUtf8.constData(), kCFStringEncodingUTF8);

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
    QString serviceName_ = QStringLiteral("localvault-vault");
};

#elif defined(Q_OS_WIN)
#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QStandardPaths>
#include <windows.h>
#include <dpapi.h>

class SystemKeychainBackend::Impl {
public:
    Impl()
    {
        const QString configDir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
        directory_ = configDir + QStringLiteral("/emk");
    }

    bool isAvailable() const
    {
        return true;
    }

    bool store(const QString &key, const QByteArray &data)
    {
        DATA_BLOB in;
        in.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(data.constData()));
        in.cbData = static_cast<DWORD>(data.size());

        DATA_BLOB out;
        if (!CryptProtectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
            return false;
        }

        QByteArray encrypted(reinterpret_cast<char *>(out.pbData), static_cast<int>(out.cbData));
        LocalFree(out.pbData);

        QDir dir(directory_);
        if (!dir.exists() && !dir.mkpath(".")) {
            return false;
        }

        const QString path = directory_ + "/" + sanitizeKey(key);
        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly)) {
            return false;
        }
        file.write(encrypted);
        return file.commit();
    }

    QByteArray load(const QString &key)
    {
        const QString path = directory_ + "/" + sanitizeKey(key);
        QFile file(path);
        if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
            return QByteArray();
        }

        QByteArray encrypted = file.readAll();
        DATA_BLOB in;
        in.pbData = reinterpret_cast<BYTE *>(encrypted.data());
        in.cbData = static_cast<DWORD>(encrypted.size());

        DATA_BLOB out;
        if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
            return QByteArray();
        }

        QByteArray data(reinterpret_cast<char *>(out.pbData), static_cast<int>(out.cbData));
        LocalFree(out.pbData);
        return data;
    }

    bool remove(const QString &key)
    {
        const QString path = directory_ + "/" + sanitizeKey(key);
        return QFile::remove(path);
    }

private:
    QString directory_;

    static QString sanitizeKey(const QString &key)
    {
        QString safe = key;
        safe.replace('/', '_');
        safe.replace('\\', '_');
        safe.replace(':', '_');
        return safe;
    }
};

#else
class SystemKeychainBackend::Impl {
public:
    bool isAvailable() const
    {
        return false;
    }

    bool store(const QString &, const QByteArray &)
    {
        return false;
    }

    QByteArray load(const QString &)
    {
        return QByteArray();
    }

    bool remove(const QString &)
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

QString SystemKeychainBackend::name() const
{
#if defined(Q_OS_LINUX)
    return QStringLiteral("system-keychain-libsecret");
#elif defined(Q_OS_MACOS)
    return QStringLiteral("system-keychain-macos");
#elif defined(Q_OS_WIN)
    return QStringLiteral("system-keychain-dpapi");
#else
    return QStringLiteral("system-keychain-unavailable");
#endif
}

bool SystemKeychainBackend::store(const QString &key, const QByteArray &data)
{
    return impl_->store(key, data);
}

QByteArray SystemKeychainBackend::load(const QString &key)
{
    return impl_->load(key);
}

bool SystemKeychainBackend::remove(const QString &key)
{
    return impl_->remove(key);
}
