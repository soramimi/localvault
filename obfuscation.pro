DESTDIR = $$PWD
TEMPLATE = app
TARGET = obfuscation
QT += core widgets
CONFIG += c++17
CONFIG -= app_bundle
CONFIG += link_pkgconfig
PKGCONFIG += libsodium

HEADERS += \
	gui/PinDialog.h \
	vault/SecretStorage.h \
	vault/SecureBuffer.h \
	vault/Vault.h \
	storage/FileBackend.h \
	storage/SystemKeychainBackend.h

SOURCES += \
	gui/PinDialog.cpp \
	vault/SecureBuffer.cpp \
	vault/Vault.cpp \
	storage/FileBackend.cpp \
	storage/SystemKeychainBackend.cpp \
	main.cpp

linux {
	PKGCONFIG += libsecret-1
}
macx {
	LIBS += -framework Security -framework CoreFoundation
}
win32 {
	LIBS += -lcrypt32
}
