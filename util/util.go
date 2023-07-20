package util

import (
	"bufio"
	"bytes"
	"net/http"
)

func ParseHTTPRequest(requestBytes []byte) (*http.Request, error) {
	// Parse the request using the http.ReadRequest function
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(requestBytes)))
	if err != nil {
		return nil, err
	}

	return request, nil
}

func ParseHTTPResponse(data []byte, request *http.Request) (*http.Response, error) {
	buffer := bytes.NewBuffer(data)
	reader := bufio.NewReader(buffer)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func ExtractLastResponse(data []byte) []byte {
	marker := []byte("HTTP/")

	// Find the last occurrence of the marker.
	position := bytes.LastIndex(data, marker)

	// If marker not found, return nil.
	if position == -1 {
		return nil
	}

	// Return the data slice starting from the found position.
	return data[position:]
}
