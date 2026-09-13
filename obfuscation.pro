DESTDIR = $$PWD
TEMPLATE = app
TARGET = obfuscation
QT += core widgets
CONFIG += c++17
CONFIG -= app_bundle

HEADERS += \
	gui/PinDialog.h \
	vault/ChaCha20.h \
	vault/Kdf.h \
	vault/Mac.h \
	vault/SecretStorage.h \
	vault/SecureBuffer.h \
	vault/Vault.h \
	storage/FileBackend.h \
	storage/SystemKeychainBackend.h

SOURCES += \
	gui/PinDialog.cpp \
	vault/ChaCha20.cpp \
	vault/Kdf.cpp \
	vault/Mac.cpp \
	vault/SecureBuffer.cpp \
	vault/Vault.cpp \
	storage/FileBackend.cpp \
	storage/SystemKeychainBackend.cpp \
	main.cpp

linux {
	CONFIG += link_pkgconfig
	PKGCONFIG += libsecret-1
}
macx {
	LIBS += -framework Security -framework CoreFoundation
}
win32 {
	LIBS += -lcrypt32
}
