/*
 * Package sm4 implements the Chinese SM4 Digest Algorithm,
 * according to "go/src/crypto/aes"
 * author: weizhang <d5c5ceb0@gmail.com>
 * 2017.02.24
 */

package sm4

import (
	"strconv"
)

// The SM4 block size in bytes.
const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
	return "sm4: invalid key size " + strconv.Itoa(int(k))
}

// sm4Cipher is an instance of SM4 encryption.
type Sm4Cipher struct {
	subkeys [32]uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (*Sm4Cipher, error) {
	if len(key) != 16 {
		return nil, KeySizeError(len(key))
	}

	c := new(Sm4Cipher)
	c.generateSubkeys(key)
	return c, nil
}

func (c *Sm4Cipher) BlockSize() int { return BlockSize }

func (c *Sm4Cipher) Encrypt(dst, src []byte) { encryptBlock(c.subkeys[:], dst, src) }

func (c *Sm4Cipher) Decrypt(dst, src []byte) { decryptBlock(c.subkeys[:], dst, src) }