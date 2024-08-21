package otp4ruts

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
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
	return hex.EncodeToString(HmacOUT256(key, []byte(utils.GetTimeStamp(time.Now()))))
}

func ChkOTP256Hex(text []byte, key []byte, chk string) bool {
	return OTP256Hex(text, key) == chk
}

func ChkTimeOTP256Hex(key []byte, chk string, timerange int) bool {
	t := time.Now()
	for i := (-1 * timerange); i <= timerange; i++ {
		tx := t.Add(time.Duration(i) * time.Second)
		if OTP256Hex([]byte(utils.GetTimeStamp(tx)), key) == chk {
			return true
		}
	}
	return false
}

// Standard OTP

func HmacOUT(secret []byte, data []byte) []byte {
	h := hmac.New(sha512.New, secret)
	h.Write(data)
	return h.Sum(nil)
}

func OTP(secret []byte, data []byte) uint64 {
	return binary.LittleEndian.Uint64(HmacOUT(secret, data)[:8])
}

func OTPxMOD(secret []byte, data []byte, mod uint64) uint64 {
	return OTP(secret, data) % mod
}

func OTPxHex(secret []byte, data []byte, size int) string {
	return hex.EncodeToString(HmacOUT(secret, data)[:size])
}

func ChkOTP(secret []byte, data []byte, chk uint64) bool {
	return OTP(secret, data) == chk
}

func ChkOTPxMOD(secret []byte, data []byte, mod uint64, chk uint64) bool {
	return OTPxMOD(secret, data, mod) == chk
}

func ChkOTPxHex(secret []byte, data []byte, size int, chk string) bool {
	return OTPxHex(secret, data, size) == chk
}

func TimeOTP(data []byte) uint64 {
	return OTP([]byte(utils.GetTimeStamp(time.Now())), data)
}

func TimeOTPxMOD(data []byte, mod uint64) uint64 {
	return OTPxMOD([]byte(utils.GetTimeStamp(time.Now())), data, mod)
}

func TimeOTPxHex(data []byte, size int) string {
	return OTPxHex([]byte(utils.GetTimeStamp(time.Now())), data, size)
}

func ChkTimeOTP(data []byte, chk uint64, timerange int) bool {
	t := time.Now()
	for i := (-1 * timerange); i <= timerange; i++ {
		tx := t.Add(time.Duration(i) * time.Second)
		if OTP([]byte(utils.GetTimeStamp(tx)), data) == chk {
			return true
		}
	}
	return false
}

func ChkTimeOTPxMOD(data []byte, mod uint64, chk uint64, timerange int) bool {
	t := time.Now()
	for i := (-1 * timerange); i <= timerange; i++ {
		tx := t.Add(time.Duration(i) * time.Second)
		if OTPxMOD([]byte(utils.GetTimeStamp(tx)), data, mod) == chk {
			return true
		}
	}
	return false
}

func ChkTimeOTPxHex(data []byte, size int, chk string, timerange int) bool {
	t := time.Now()
	for i := (-1 * timerange); i <= timerange; i++ {
		tx := t.Add(time.Duration(i) * time.Second)
		if OTPxHex([]byte(utils.GetTimeStamp(tx)), data, size) == chk {
			return true
		}
	}
	return false
}
