package utils

import "os"

func UserHomeDir() string {
	return os.Getenv("HOME")
}
