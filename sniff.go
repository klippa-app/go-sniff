package main

import (
	"bytes"
	"net/http"
)

// DetectContentType wraps http.DetectContentType
func DetectContentType(data []byte) string {

	// Detect UTF8 BOM
	if len(data) > 3 && bytes.Equal(data[0:3], []byte{0xEF, 0xBB, 0xBF}) {
		data = data[3:]
	}

	contentType := http.DetectContentType(data)

	if isNonFallback(contentType) {
		return contentType
	}

	// Get the index of the first non-whitespace byte in data.
	firstNonWS := 0
	for ; firstNonWS < len(data) && isWS(data[firstNonWS]); firstNonWS++ {
	}

	// Try to detect the Content-Type using a signature. Some PDF generators add their own bytes prior to the signature bytes.
	// This is accounted for repeatedly sniffing the bytes with an increasing starting offset
	maxOffset := firstNonWS + 10

	if maxOffset >= len(data) {
		return contentType
	}

	for offset := firstNonWS; offset <= maxOffset; offset++ {
		// Try to detect a new Content-Type with an offset
		newContentType := http.DetectContentType(data[offset:])
		if isNonFallback(newContentType) {
			return newContentType
		}
	}

	return contentType
}

func isWS(b byte) bool {
	switch b {
	case '\t', '\n', '\x0c', '\r', ' ':
		return true
	}
	return false
}

// isNonFallback detects fallback returned by http.DetectContentType
func isNonFallback(contentType string) bool {
	return contentType != "application/octet-stream" && contentType != "text/plain; charset=utf-8"
}

