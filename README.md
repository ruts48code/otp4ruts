# otp4ruts

*This library is made for personal used. You may modify or use it by your own risk.*

## About
This is a library for generate token in time based on HMAC base.

## Usage

Hex string time-based token for Machine to Machine API Communication
```go
package main
import (
  tk "github.com/ruts48code/otp4ruts"
  "fmt"
  "time"
)

func main(){
  secret := []byte("secretrandomtext")
  sizeToken := 8
  timeRange := 5 // check token that is valid within +/- 5 seconds

  // Get token
  token := tk.TimeOTPxHex(secret, sizeToken)
  fmt.Printf("Token is %s\n", token)

  time.Sleep(2 * time.Second)

  // Check token
  if tk.ChkTimeOTPxHex(secret, sizeToken, token, timeRange) {
    fmt.Printf("Token is valid\n")
  }else{
    fmt.Printf("Token is invalid\n")
  }
}
```


