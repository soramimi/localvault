DESTDIR = $$PWD/../_bin
TEMPLATE = app
TARGET = localvault
QT += core widgets
CONFIG += c++17
CONFIG -= app_bundle
linux|macx:CONFIG += link_pkgconfig

msvc:INCLUDEPATH += C:/vcpkg/installed/x64-windows/include
msvc:CONFIG(debug,debug|release) {
	LIBS += -LC:/vcpkg/installed/x64-windows/debug/lib
}

msvc:CONFIG(release,debug|release) {
	LIBS += -LC:/vcpkg/installed/x64-windows/lib
}


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
	PKGCONFIG += libsodium
}
macx {
	LIBS += -framework Security -framework CoreFoundation
}
win32 {
	LIBS += -lcrypt32 -llibsodium
	# テスト出力をコンソールに表示するため（GUI デモ時もコンソールウィンドウが表示される）
	CONFIG += console
}

DISTFILES += \
	../AGENTS.md \
	../README.md
