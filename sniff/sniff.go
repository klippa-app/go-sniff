package sniff

import (
	"bytes"
	"net/http"
)

// DetectContentType wraps http.DetectContentType and offers a fallback for PDF detection.
func DetectContentType(assumedContentType string, startData, endData []byte) string {
	// It's possible there is garbage around a PDF file, which makes it still
	// viewable as PDF, but the sniffer would return a different contentType.
	if (isPDFContentType(assumedContentType) || isFallbackContentType(assumedContentType)) && endData != nil && bytes.Contains(endData, []byte("%%EOF")) {
		return "application/pdf"
	}

	// Detect UTF8 BOM
	if len(startData) > 3 && bytes.Equal(startData[0:3], []byte{0xEF, 0xBB, 0xBF}) {
		startData = startData[3:]
	}

	contentType := http.DetectContentType(startData)

	if !isFallbackContentType(contentType) {
		return contentType
	}

	// Get the index of the first non-whitespace byte in data.
	firstNonWS := 0
	for ; firstNonWS < len(startData) && isWS(startData[firstNonWS]); firstNonWS++ {
	}

	// Try to detect the Content-Type using a signature. Some PDF generators add their own bytes prior to the signature bytes.
	// This is accounted for repeatedly sniffing the bytes with an increasing starting offset
	maxOffset := firstNonWS + 10

	if maxOffset >= len(startData) {
		return contentType
	}

	for offset := firstNonWS; offset <= maxOffset; offset++ {
		// Try to detect a new Content-Type with an offset
		newContentType := http.DetectContentType(startData[offset:])
		if !isFallbackContentType(newContentType) {
			return newContentType
		}
	}

	if endData != nil && bytes.Contains(endData, []byte("%%EOF")) {
		return "application/pdf"
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

// isPDFContentType detects whether a content type is one of the valid pdf content types
func isPDFContentType(contentType string) bool {
	return contentType == "application/x-pdf" || contentType == "application/pdf" || contentType == "x-application/apple-pdf"
}

// isFallbackContentType detects fallback returned by http.DetectContentType
func isFallbackContentType(contentType string) bool {
	return contentType == "application/octet-stream" || contentType == "text/plain; charset=utf-8"
}
