HEADERS += \
	$$LOCALVAULT_SRC/app/BackendSelector.h \
	$$LOCALVAULT_SRC/gui/PinDialog.h \
	$$LOCALVAULT_SRC/gui/SecurePinEdit.h \
	$$LOCALVAULT_SRC/vault/ProcessHardening.h \
	$$LOCALVAULT_SRC/vault/SecretStorage.h \
	$$LOCALVAULT_SRC/vault/SecureBuffer.h \
	$$LOCALVAULT_SRC/vault/Vault.h \
	$$LOCALVAULT_SRC/storage/AtomicFile.h \
	$$LOCALVAULT_SRC/storage/FileBackend.h \
	$$LOCALVAULT_SRC/storage/SystemKeychainBackend.h

SOURCES += \
	$$LOCALVAULT_SRC/app/BackendSelector.cpp \
	$$LOCALVAULT_SRC/gui/PinDialog.cpp \
	$$LOCALVAULT_SRC/gui/SecurePinEdit.cpp \
	$$LOCALVAULT_SRC/vault/ProcessHardening.cpp \
	$$LOCALVAULT_SRC/vault/SecureBuffer.cpp \
	$$LOCALVAULT_SRC/vault/Vault.cpp \
	$$LOCALVAULT_SRC/storage/AtomicFile.cpp \
	$$LOCALVAULT_SRC/storage/FileBackend.cpp \
	$$LOCALVAULT_SRC/storage/SystemKeychainBackend.cpp

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

