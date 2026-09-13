DESTDIR = $$PWD
TEMPLATE = app
TARGET = localvault
QT += core widgets
CONFIG += c++17
CONFIG -= app_bundle
CONFIG += link_pkgconfig
PKGCONFIG += libsodium

HEADERS += \
	../src/gui/PinDialog.h \
	../src/vault/SecretStorage.h \
	../src/vault/SecureBuffer.h \
	../src/vault/Vault.h \
	../src/storage/FileBackend.h \
	../src/storage/SystemKeychainBackend.h

SOURCES += \
	../src/gui/PinDialog.cpp \
	../src/vault/SecureBuffer.cpp \
	../src/vault/Vault.cpp \
	../src/storage/FileBackend.cpp \
	../src/storage/SystemKeychainBackend.cpp \
	../src/main.cpp

linux {
	PKGCONFIG += libsecret-1
}
macx {
	LIBS += -framework Security -framework CoreFoundation
}
win32 {
	LIBS += -lcrypt32
}
