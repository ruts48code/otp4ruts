package hmac2otp0ruts

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"time"
)

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
	return OTP([]byte(getTimeStamp(time.Now())), data)
}

func TimeOTPxMOD(data []byte, mod uint64) uint64 {
	return OTPxMOD([]byte(getTimeStamp(time.Now())), data, mod)
}

func TimeOTPxHex(data []byte, size int) string {
	return OTPxHex([]byte(getTimeStamp(time.Now())), data, size)
}

func ChkTimeOTP(data []byte, chk uint64, timerange int) bool {
	t := time.Now()
	for i := (-1 * timerange); i <= timerange; i++ {
		tx := t.Add(time.Duration(i) * time.Second)
		if OTP([]byte(getTimeStamp(tx)), data) == chk {
			return true
		}
	}
	return false
}

func ChkTimeOTPxMOD(data []byte, mod uint64, chk uint64, timerange int) bool {
	t := time.Now()
	for i := (-1 * timerange); i <= timerange; i++ {
		tx := t.Add(time.Duration(i) * time.Second)
		if OTPxMOD([]byte(getTimeStamp(tx)), data, mod) == chk {
			return true
		}
	}
	return false
}

func ChkTimeOTPxHex(data []byte, size int, chk string, timerange int) bool {
	t := time.Now()
	for i := (-1 * timerange); i <= timerange; i++ {
		tx := t.Add(time.Duration(i) * time.Second)
		if OTPxHex([]byte(getTimeStamp(tx)), data, size) == chk {
			return true
		}
	}
	return false
}
