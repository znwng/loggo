package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	saltSize  = 16
	nonceSize = 12
	keySize   = 32

	// Argon2id parameters.
	memory      = 64 * 1024 // 64 MiB
	iterations  = 3
	parallelism = 2
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
)

var journalDir = filepath.Join(os.Getenv("HOME"), "journal")

// deriveKey derives a 256-bit AES key from the password using Argon2id.
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		keySize,
	)
}

// encrypt encrypts plaintext using Argon2id + AES-256-GCM.
//
// File format:
//
//	[16-byte salt][12-byte nonce][ciphertext + 16-byte GCM tag]
func encrypt(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)

	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)

	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends the 16-byte GCM authentication tag
	// to the ciphertext.
	ciphertext := gcm.Seal(
		nil,
		nonce,
		plaintext,
		nil,
	)

	result := make(
		[]byte,
		0,
		saltSize+nonceSize+len(ciphertext),
	)

	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decrypt decrypts a journal using the fixed file format:
//
//	[16-byte salt][12-byte nonce][ciphertext + 16-byte GCM tag]
func decrypt(data []byte, password string) ([]byte, error) {
	// AES-GCM's authentication tag is 16 bytes.
	const gcmTagSize = 16

	minSize := saltSize + nonceSize + gcmTagSize

	if len(data) < minSize {
		return nil, errors.New(
			"invalid or corrupted journal",
		)
	}

	saltStart := 0
	saltEnd := saltStart + saltSize

	nonceStart := saltEnd
	nonceEnd := nonceStart + nonceSize

	salt := data[saltStart:saltEnd]
	nonce := data[nonceStart:nonceEnd]
	ciphertext := data[nonceEnd:]

	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf(
			"create AES cipher: %w",
			err,
		)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf(
			"create GCM: %w",
			err,
		)
	}

	plaintext, err := gcm.Open(
		nil,
		nonce,
		ciphertext,
		nil,
	)
	if err != nil {
		return nil, errors.New(
			"incorrect password or corrupted journal",
		)
	}

	return plaintext, nil
}

// readPassword asks for a password without displaying it.
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		return "", fmt.Errorf(
			"read password: %w",
			err,
		)
	}

	if len(password) == 0 {
		return "", errors.New(
			"password cannot be empty",
		)
	}

	return string(password), nil
}

// readNewPassword asks for and confirms a new password.
func readNewPassword() (string, error) {
	password, err := readPassword("New password: ")
	if err != nil {
		return "", err
	}

	confirmation, err := readPassword(
		"Confirm new password: ",
	)
	if err != nil {
		return "", err
	}

	if password != confirmation {
		return "", errors.New(
			"passwords do not match",
		)
	}

	return password, nil
}

// createJournal creates a new encrypted journal.
func createJournal() error {
	password, err := readPassword(
		"Journal password: ",
	)
	if err != nil {
		return err
	}

	tempFile, err := os.CreateTemp(
		"",
		"loggo-*",
	)
	if err != nil {
		return fmt.Errorf(
			"create temporary file: %w",
			err,
		)
	}

	tempPath := tempFile.Name()

	defer os.Remove(tempPath)

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf(
			"close temporary file: %w",
			err,
		)
	}

	editor := exec.Command(
		"nvim",
		tempPath,
	)

	editor.Stdin = os.Stdin
	editor.Stdout = os.Stdout
	editor.Stderr = os.Stderr

	if err := editor.Run(); err != nil {
		return fmt.Errorf(
			"run nvim: %w",
			err,
		)
	}

	plaintext, err := os.ReadFile(tempPath)
	if err != nil {
		return fmt.Errorf(
			"read journal: %w",
			err,
		)
	}

	encrypted, err := encrypt(
		plaintext,
		password,
	)
	if err != nil {
		return fmt.Errorf(
			"encrypt journal: %w",
			err,
		)
	}

	if err := os.MkdirAll(
		journalDir,
		0700,
	); err != nil {
		return fmt.Errorf(
			"create journal directory: %w",
			err,
		)
	}

	filename := time.Now().Format(
		"020106_150405",
	)

	journalPath := filepath.Join(
		journalDir,
		filename,
	)

	if err := writeAtomic(
		journalPath,
		encrypted,
	); err != nil {
		return fmt.Errorf(
			"write journal: %w",
			err,
		)
	}

	fmt.Printf(
		"Journal saved: %s\n",
		journalPath,
	)

	return nil
}

// readJournals decrypts all journals matching DDMMYY.
func readJournals(prefix string) error {
	password, err := readPassword(
		"Journal password: ",
	)
	if err != nil {
		return err
	}

	pattern := filepath.Join(
		journalDir,
		prefix+"_*",
	)

	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf(
			"find journals: %w",
			err,
		)
	}

	if len(files) == 0 {
		return fmt.Errorf(
			"no journals found for date: %s",
			prefix,
		)
	}

	sort.Strings(files)

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf(
				"read %s: %w",
				filepath.Base(file),
				err,
			)
		}

		plaintext, err := decrypt(
			data,
			password,
		)
		if err != nil {
			return fmt.Errorf(
				"%s: %w",
				filepath.Base(file),
				err,
			)
		}

		fmt.Println()

		fmt.Printf(
			"%s***** %s *****%s\n",
			colorYellow,
			filepath.Base(file),
			colorReset,
		)

		fmt.Print(string(plaintext))

		if len(plaintext) > 0 &&
			!strings.HasSuffix(
				string(plaintext),
				"\n",
			) {
			fmt.Println()
		}
	}

	return nil
}

// encryptOldJournals encrypts existing plaintext journal files.
//
// This command is intended for plaintext journals only.
// Because the new format has no magic/version/header, this
// function deliberately does not try to detect encryption.
// It should therefore only be used when the journal directory
// contains known plaintext files.
func encryptOldJournals() error {
	password, err := readPassword(
		"Journal password: ",
	)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(journalDir)
	if err != nil {
		return fmt.Errorf(
			"read journal directory: %w",
			err,
		)
	}

	var files []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !isJournalFilename(entry.Name()) {
			continue
		}

		files = append(
			files,
			filepath.Join(
				journalDir,
				entry.Name(),
			),
		)
	}

	sort.Strings(files)

	if len(files) == 0 {
		fmt.Println("No journal files found.")
		return nil
	}

	for _, file := range files {
		name := filepath.Base(file)

		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf(
				"read %s: %w",
				name,
				err,
			)
		}

		encrypted, err := encrypt(
			data,
			password,
		)
		if err != nil {
			return fmt.Errorf(
				"encrypt %s: %w",
				name,
				err,
			)
		}

		if err := writeAtomic(
			file,
			encrypted,
		); err != nil {
			return fmt.Errorf(
				"replace %s: %w",
				name,
				err,
			)
		}

		fmt.Printf(
			"%sEncrypted:%s %s\n",
			colorYellow,
			colorReset,
			name,
		)
	}

	fmt.Println()

	fmt.Printf(
		"%sMigration complete.%s\n",
		colorYellow,
		colorReset,
	)

	return nil
}

// changePassword changes the password for every journal.
//
// Every journal is decrypted successfully before any file
// is modified. This prevents a partial password migration
// caused by discovering a bad password halfway through.
func changePassword() error {
	oldPassword, err := readPassword(
		"Current password: ",
	)
	if err != nil {
		return err
	}

	files, err := journalFiles()
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return errors.New(
			"no journal files found",
		)
	}

	type journal struct {
		path      string
		plaintext []byte
	}

	journals := make(
		[]journal,
		0,
		len(files),
	)

	// ----------------------------------------
	// Verify and decrypt everything first.
	// ----------------------------------------

	for _, file := range files {
		name := filepath.Base(file)

		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf(
				"read %s: %w",
				name,
				err,
			)
		}

		plaintext, err := decrypt(
			data,
			oldPassword,
		)
		if err != nil {
			return fmt.Errorf(
				"cannot verify %s: %w",
				name,
				err,
			)
		}

		journals = append(
			journals,
			journal{
				path:      file,
				plaintext: plaintext,
			},
		)
	}

	fmt.Printf(
		"%sVerified %d journal(s).%s\n",
		colorYellow,
		len(journals),
		colorReset,
	)

	newPassword, err := readNewPassword()
	if err != nil {
		return err
	}

	if newPassword == oldPassword {
		return errors.New(
			"new password must be different from the current password",
		)
	}

	// ----------------------------------------
	// Re-encrypt everything with new password.
	// ----------------------------------------

	for _, journal := range journals {
		name := filepath.Base(journal.path)

		encrypted, err := encrypt(
			journal.plaintext,
			newPassword,
		)
		if err != nil {
			return fmt.Errorf(
				"encrypt %s with new password: %w",
				name,
				err,
			)
		}

		if err := writeAtomic(
			journal.path,
			encrypted,
		); err != nil {
			return fmt.Errorf(
				"update %s: %w",
				name,
				err,
			)
		}

		fmt.Printf(
			"%sUpdated:%s %s\n",
			colorYellow,
			colorReset,
			name,
		)
	}

	// Best-effort cleanup of plaintext copies held in memory.
	for i := range journals {
		for j := range journals[i].plaintext {
			journals[i].plaintext[j] = 0
		}
	}

	fmt.Println()

	fmt.Printf(
		"%sPassword changed successfully.%s\n",
		colorYellow,
		colorReset,
	)

	return nil
}

// journalFiles returns all journal files.
func journalFiles() ([]string, error) {
	entries, err := os.ReadDir(journalDir)
	if err != nil {
		return nil, fmt.Errorf(
			"read journal directory: %w",
			err,
		)
	}

	var files []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !isJournalFilename(entry.Name()) {
			continue
		}

		files = append(
			files,
			filepath.Join(
				journalDir,
				entry.Name(),
			),
		)
	}

	sort.Strings(files)

	return files, nil
}

// writeAtomic writes data to a temporary file, syncs it,
// and then atomically replaces the destination.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	tempFile, err := os.CreateTemp(
		dir,
		".loggo-*",
	)
	if err != nil {
		return err
	}

	tempPath := tempFile.Name()

	cleanup := func() {
		tempFile.Close()
		os.Remove(tempPath)
	}

	if err := tempFile.Chmod(0600); err != nil {
		cleanup()
		return err
	}

	if _, err := tempFile.Write(data); err != nil {
		cleanup()
		return err
	}

	if err := tempFile.Sync(); err != nil {
		cleanup()
		return err
	}

	if err := tempFile.Close(); err != nil {
		os.Remove(tempPath)
		return err
	}

	if err := os.Rename(
		tempPath,
		path,
	); err != nil {
		os.Remove(tempPath)
		return err
	}

	return nil
}

// isJournalFilename checks for the DDMMYY_HHMMSS format.
func isJournalFilename(name string) bool {
	if len(name) != len("031026_160043") {
		return false
	}

	if name[6] != '_' {
		return false
	}

	for i, c := range name {
		if i == 6 {
			continue
		}

		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  loggo                  Create a new journal")
	fmt.Println("  loggo DDMMYY           Read journals from that date")
	fmt.Println("  loggo encrypt-old      Encrypt old plaintext journals")
	fmt.Println("  loggo change-password  Change journal password")
}

func main() {
	switch len(os.Args) {
	case 1:
		if err := createJournal(); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\n%sError: %v%s\n",
				colorRed,
				err,
				colorReset,
			)
			os.Exit(1)
		}

	case 2:
		switch os.Args[1] {
		case "encrypt-old":
			if err := encryptOldJournals(); err != nil {
				fmt.Fprintf(
					os.Stderr,
					"\n%sError: %v%s\n",
					colorRed,
					err,
					colorReset,
				)
				os.Exit(1)
			}

		case "change-password":
			if err := changePassword(); err != nil {
				fmt.Fprintf(
					os.Stderr,
					"\n%sError: %v%s\n",
					colorRed,
					err,
					colorReset,
				)
				os.Exit(1)
			}

		default:
			if err := readJournals(
				os.Args[1],
			); err != nil {
				fmt.Fprintf(
					os.Stderr,
					"\n%sError: %v%s\n",
					colorRed,
					err,
					colorReset,
				)
				os.Exit(1)
			}
		}

	default:
		usage()
		os.Exit(1)
	}
}
