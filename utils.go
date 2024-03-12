package otp4ruts

import "time"

func getTimeStamp(t time.Time) string {
	return t.Format("2006-01-02T15:04:05")
}
