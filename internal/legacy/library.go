// Package legacy reads the old XDial's profile library and turns it into a
// configuration and the secrets it uses, ARCHITECTURE.md 4.8. It runs as the
// user, who owns the library and the keychain item holding its key; the
// daemon never reads either.
package legacy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// The library is one AES-256-GCM sealed box, nonce first, authenticating
// this string, with a random key kept in the user's keychain.
const (
	aad            = "XDial Profile Library v1"
	keychainItem   = "com.kafeifei.xdial.configuration"
	keychainLabel  = "profile-library-key-v1"
	maxLibrarySize = 32<<20 + 28
)

// Path is where the old XDial keeps the library for home.
func Path(home string) string {
	return filepath.Join(home, ".xdial", "configuration", "profiles.enc")
}

// Read decrypts the library at path with the key from the user's keychain.
// The plaintext stays in memory; nothing is written.
func Read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sealed, err := io.ReadAll(io.LimitReader(f, maxLibrarySize+1))
	if err != nil {
		return nil, err
	}
	if len(sealed) > maxLibrarySize {
		return nil, errors.New("旧配置库超过大小上限")
	}
	key, err := keychainKey()
	if err != nil {
		return nil, err
	}
	return Open(sealed, key)
}

// Open decrypts a sealed library with key.
func Open(sealed, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("旧配置库太短，不是加密的配置库")
	}
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(aad))
	if err != nil {
		return nil, errors.New("旧配置库解不开：钥匙串里的密钥和它对不上，或者文件坏了")
	}
	return plain, nil
}

// keychainKey asks the keychain for the library's key; macOS asks the user
// to allow it the first time. security prints a key that is not text in hex.
func keychainKey() ([]byte, error) {
	out, err := exec.Command("/usr/bin/security", "find-generic-password", "-s", keychainItem, "-a", keychainLabel, "-w").Output()
	if err != nil {
		return nil, fmt.Errorf("读不到钥匙串里旧配置库的密钥（%s）：没有这一项，或者没有允许", keychainItem)
	}
	key := bytes.TrimSuffix(out, []byte("\n"))
	if len(key) == 64 {
		if decoded, err := hex.DecodeString(string(key)); err == nil {
			key = decoded
		}
	}
	if len(key) != 32 {
		return nil, errors.New("钥匙串里旧配置库的密钥长度不对")
	}
	return key, nil
}
