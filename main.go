package otp4ruts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"

	utils "github.com/ruts48code/utils4ruts"
)

// OTP for RUTS sha256

func HmacOUT256(secret []byte, data []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return h.Sum(nil)
}

func OTP256Hex(text []byte, key []byte) string {
	return hex.EncodeToString(HmacOUT256(key, text))
}

func TimeOTP256Hex(key []byte) string {
	return hex.EncodeToString(HmacOUT256(key, []byte(utils.GetUnixTime(time.Now()))))
}

func ChkOTP256Hex(text []byte, key []byte, chk string) bool {
	return OTP256Hex(text, key) == chk
}

func ChkTimeOTP256Hex(key []byte, chk string, timerange int) bool {
	t := time.Now()
	for i := (-1 * timerange); i <= timerange; i++ {
		tx := t.Add(time.Duration(i) * time.Second)
		if OTP256Hex([]byte(utils.GetUnixTime(tx)), key) == chk {
			return true
		}
	}
	return false
}
