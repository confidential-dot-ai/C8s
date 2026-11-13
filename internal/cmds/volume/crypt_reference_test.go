package volume

import (
	"crypto/aes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/xts"
)

// encrypt and decrypt are the serial reference EncryptAt is compared against.
func encrypt(dst io.Writer, src io.Reader, key []byte) error {
	return transform(dst, src, key, (*xts.Cipher).Encrypt)
}

func decrypt(dst io.Writer, src io.Reader, key []byte) error {
	return transform(dst, src, key, (*xts.Cipher).Decrypt)
}

func transform(dst io.Writer, src io.Reader, key []byte, apply func(*xts.Cipher, []byte, []byte, uint64)) error {
	if len(key) != KeyBytes {
		return fmt.Errorf("volume: key is %d bytes, want %d", len(key), KeyBytes)
	}
	cipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return fmt.Errorf("volume: init xts: %w", err)
	}

	in := make([]byte, SectorSize)
	out := make([]byte, SectorSize)
	for sector := uint64(0); ; sector++ {
		n, err := io.ReadFull(src, in)
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case errors.Is(err, io.ErrUnexpectedEOF):
			return fmt.Errorf("%w: trailing %d bytes", ErrUnaligned, n)
		case err != nil:
			return fmt.Errorf("volume: read sector %d: %w", sector, err)
		}
		apply(cipher, out, in, sector)
		if _, err := dst.Write(out); err != nil {
			return fmt.Errorf("volume: write sector %d: %w", sector, err)
		}
	}
}
