# Obfuscation / Local Vault

ローカルデスクトップGUIアプリケーション向けの、APIキー等の機密情報を安全に管理するための実装サンプルです。

単純な難読化（XOR + 固定シード）から脱却し、ChaCha20 / HMAC-SHA256 / PBKDF2-SHA256 を用いた暗号化ベースの Vault 機能へ移行・拡張したものです。

## 目的

- APIキー等の機密情報を、PIN入力を条件に安全に暗号化/復号する
- OSが提供するセキュアストレージを優先的に利用する
- OSセキュアストレージが利用できない環境では、暗号化ファイルによるフォールバックを提供する
- Vault コアは QtCore のみに依存し、GUI 部分は QtWidgets に限定する

## アーキテクチャ

### 2段階鍵体系

```
┌─────────┐     KDF      ┌─────┐
│   PIN   │ ───────────> │ KEK │
└─────────┘  + salt      └─────┘
                             │
┌─────────┐  ChaCha20+MAC   ▼
│    MK   │ <───────────  EMK
│(random) │               (secure storage)
└────┬────┘
     │ ChaCha20+MAC
     ▼
[encrypted data file]
```

- **MK（Master Key）**: ランダム 256bit。実際の機密データを暗号化
- **KEK（Key Encryption Key）**: PIN から PBKDF2-SHA256 で導出
- **EMK（Encrypted Master Key）**: KEK で暗号化された MK。セキュアストレージバックエンドに保存
- PIN 変更時は EMK のみ再暗号化すればよく、全データの再暗号化は不要

### レイヤー構成

```
┌─────────────────────────────────────┐
│ GUI Layer (QtWidgets)               │
│  - PinDialog                          │
├─────────────────────────────────────┤
│ Application Layer                   │
│  - Vault API                          │
├─────────────────────────────────────┤
│ Core Vault Module (QtCore only)     │
│  - SecureBuffer, ChaCha20, Kdf, Mac   │
├─────────────────────────────────────┤
│ Storage Backends (QtCore only)      │
│  - SystemKeychainBackend              │
│  - FileBackend (fallback)             │
└─────────────────────────────────────┘
```

## ファイル構成

```
obfuscation/
├── AGENTS.md                    # エージェント向け詳細設計書
├── README.md                    # 本ファイル
├── obfuscation.pro              # Qt qmake プロジェクト
├── main.cpp                     # テストランナー / GUI デモ
├── vault/                       # QtCore のみの Vault コア
│   ├── SecureBuffer.h/cpp
│   ├── ChaCha20.h/cpp
│   ├── Kdf.h/cpp
│   ├── Mac.h/cpp
│   ├── Vault.h/cpp
│   └── SecretStorage.h
├── storage/                     # ストレージバックエンド
│   ├── FileBackend.h/cpp
│   └── SystemKeychainBackend.h/cpp
└── gui/                         # GUI レイヤー（QtWidgets）
    └── PinDialog.h/cpp
```

## ビルド手順

### 前提

- Qt 5.12 以上、または Qt 6
- Linux では libsecret / glib の開発ファイル

### Linux

```bash
# Ubuntu/Debian の例
sudo apt-get install libsecret-1-dev libglib2.0-dev

# ビルド
qmake obfuscation.pro
make

# テスト実行
./obfuscation --test

# GUI デモ実行
./obfuscation
```

### macOS

```bash
qmake obfuscation.pro
make
```

### Windows

```bash
qmake obfuscation.pro
nmake  # または mingw32-make
```

## クラスの使い方

### SecureBuffer

機密データを保持するセキュアメモリコンテナ。解放時に確実にゼロクリアし、可能であればメモリロックを行う。

```cpp
#include "vault/SecureBuffer.h"

SecureBuffer buf(32);                          // 32バイト確保
std::fill(buf.begin(), buf.end(), 0xab);       // データ書き込み
buf.lock();                                    // スワップ防止（可能な場合）
// ... 使用 ...
buf.clear();                                   // 明示的に消去
```

### ChaCha20

RFC 8439 準拠のストリーム暗号。デフォルトコンストラクタでは CSPRNG として動作する。

```cpp
#include "vault/ChaCha20.h"

uint8_t key[ChaCha20::KEY_SIZE] = { /* 32 bytes */ };
uint8_t nonce[ChaCha20::NONCE_SIZE] = { /* 12 bytes */ };

QByteArray plain = "secret data";
QByteArray cipher(plain.size(), 0);

ChaCha20 enc(key, nonce);
enc.crypt(reinterpret_cast<const uint8_t *>(plain.constData()),
          reinterpret_cast<uint8_t *>(cipher.data()),
          plain.size());

// 復号
QByteArray decrypted(plain.size(), 0);
ChaCha20 dec(key, nonce);
dec.crypt(reinterpret_cast<const uint8_t *>(cipher.constData()),
          reinterpret_cast<uint8_t *>(decrypted.data()),
          plain.size());
```

### Kdf / Mac

```cpp
#include "vault/Kdf.h"
#include "vault/Mac.h"

SecureBuffer password;
password.assign("password", 8);

// PBKDF2-SHA256 で 32 バイト導出
Pbkdf2Sha256 kdf(100000);
SecureBuffer key = kdf.derive(password, "salt", 32);

// HMAC-SHA256
HmacSha256 hmac;
QByteArray tag = hmac.compute(key, "message");
```

### Vault

Vault は `ISecretStorageBackend` を通じて EMK を保存する。アプリ側でバックエンドを選択する。

```cpp
#include "storage/SystemKeychainBackend.h"
#include "storage/FileBackend.h"
#include "vault/Vault.h"
#include "vault/SecureBuffer.h"

// バックエンドを選択：OSセキュアストレージ優先、不可ならファイルフォールバック
std::unique_ptr<ISecretStorageBackend> backend;
auto systemBackend = std::make_unique<SystemKeychainBackend>();
if (systemBackend->isAvailable()) {
    backend = std::move(systemBackend);
} else {
    backend = std::make_unique<FileBackend>("/path/to/emk/dir");
}

Vault vault(backend.get(), "my-app-emk");

// 初回セットアップ
SecureBuffer pin;
pin.assign("1234", 4);
if (!vault.isSetup()) {
    vault.setup(pin);
}

// 解除
vault.unlock(pin);

// 機密データの暗号化/復号
QByteArray secret = "API_KEY=sk-1234567890";
QByteArray encrypted = vault.encrypt(secret);
QByteArray decrypted = vault.decrypt(encrypted);

// PIN 変更
SecureBuffer newPin;
newPin.assign("5678", 4);
vault.changePin(pin, newPin);

// 使用後はロック
vault.lock();
```

### PinDialog

QtWidgets の PIN 入力ダイアログ。Vault から独立しており、`SecureBuffer` で PIN を返す。

```cpp
#include "gui/PinDialog.h"

// セットアップ時（2回入力で確認）
bool ok = false;
SecureBuffer pin = PinDialog::setupPin(parent, &ok);
if (ok) {
    vault.setup(pin);
}

// 解除時
SecureBuffer pin = PinDialog::requestPin(parent, &ok);
if (ok) {
    vault.unlock(pin);
}
```

### バックエンドの直接利用

```cpp
#include "storage/SystemKeychainBackend.h"
#include "storage/FileBackend.h"

SystemKeychainBackend backend;
if (backend.isAvailable()) {
    backend.store("my-key", QByteArray("encrypted-master-key-blob"));
    QByteArray loaded = backend.load("my-key");
    backend.remove("my-key");
}
```

## プラットフォームごとのセキュアストア動作の流れ

### Linux: libsecret（Secret Service API）

```
[Vault]
   │ store(EMK)
   ▼
[SystemKeychainBackend]
   │ Base64 エンコード
   ▼
[libsecret]
   │ D-Bus Secret Service
   ▼
[GNOME Keyring / KDE Wallet / keepassxc-secret-service 等]
```

- `secret_password_store_sync` でデフォルトコレクションに保存
- 属性 `key` を使って項目を識別
- 実行時に `isAvailable()` で Secret Service への接続可否を確認
- デスクトップセッションでキーリングがロックされている場合、保存/読み出しに失敗する

### macOS: Keychain Services

```
[Vault]
   │ store(EMK)
   ▼
[SystemKeychainBackend]
   ▼
[Security.framework]
   │ SecItemAdd / SecItemCopyMatching / SecItemDelete
   ▼
[macOS Keychain]
```

- `kSecClassGenericPassword` として保存
- `kSecAttrService` にアプリ識別子、`kSecAttrAccount` にキー名を使用
- ユーザーがキーチェーンをロックしている場合、OS のダイアログで解除を求められる

### Windows: DPAPI + ローカルファイル

```
[Vault]
   │ store(EMK)
   ▼
[SystemKeychainBackend]
   │ CryptProtectData（ユーザー資格情報で暗号化）
   ▼
[ローカルファイル]
   │ %AppData%/<appname>/emk/<key>
```

- DPAPI で EMK を暗号化（保護対象は現在ログイン中のユーザー）
- 暗号化済みバイナリを `%AppData%` 以下に保存
- ファイルパーミッションは OS に委ねる（必要に応じて追加設定）
- ログイン中のユーザーでないと復号できない

## セキュリティ上の注意

- 本実装はあくまで実験・サンプルコードです。本番利用の前にセキュリティレビューを行ってください。
- PIN は短いため、KEK 導出には十分なイテレーション数（最低 100,000 回以上）を設定しています。
- `FileBackend` は OS セキュアストレージが使えない場合の最後の手段として位置づけてください。
- 復号後の機密情報は `SecureBuffer` で管理し、使用後は即座に消去してください。
- 可能な限りメモリロック（`mlock` / `VirtualLock`）を利用し、スワップファイルへの漏洩を防いでください。

## ライセンス

このプロジェクトは実験的なサンプルコードです。ライセンスは別途指定がない限り、プロジェクトの所有者に帰属します。
