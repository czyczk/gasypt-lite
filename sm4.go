package gasypt

import (
	"crypto/hmac"

	"github.com/emmansun/gmsm/sm3"

	"golang.org/x/crypto/pbkdf2"
)

func deriveSM4Keys(password []byte, salt []byte, iterations int) (encKey, macKey []byte) {
	dk := pbkdf2.Key(password, salt, iterations, 48, sm3.New)
	encKey = make([]byte, 16)
	copy(encKey, dk[:16])
	macKey = make([]byte, 32)
	copy(macKey, dk[16:48])
	zeroBytes(dk)
	return
}

func sm3HMAC(key []byte, data ...[]byte) []byte {
	h := hmac.New(sm3.New, key)
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}
