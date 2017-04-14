package main

import (
	"net/url"
)

func escapeUrl(data string) string {
	return url.QueryEscape(data)
}
