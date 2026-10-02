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

# GCC 7/8 では std::filesystem 用に -lstdc++fs が必要な場合がある
# GCC 9+ では無害だが無視される
linux-g++*:LIBS += -lstdc++fs

HEADERS += \
	../src/app/BackendSelector.h \
	../src/gui/PinDialog.h \
	../src/gui/SecurePinEdit.h \
	../src/vault/ProcessHardening.h \
	../src/vault/SecretStorage.h \
	../src/vault/SecureBuffer.h \
	../src/vault/Vault.h \
	../src/storage/AtomicFile.h \
	../src/storage/FileBackend.h \
	../src/storage/SystemKeychainBackend.h

SOURCES += \
	../src/app/BackendSelector.cpp \
	../src/gui/PinDialog.cpp \
	../src/gui/SecurePinEdit.cpp \
	../src/vault/ProcessHardening.cpp \
	../src/vault/SecureBuffer.cpp \
	../src/vault/Vault.cpp \
	../src/storage/AtomicFile.cpp \
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
