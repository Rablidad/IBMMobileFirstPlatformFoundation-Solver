package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
)

func lastIndexOf[E any](s []E) (E, error) {
	if len(s) == 0 {
		var zero E
		return zero, fmt.Errorf("empty slice")
	}
	return s[len(s)-1], nil
}

func randstr(length int) string {
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset)-1)]
	}
	return string(b)
}

func chunkBy(items []string, chunkSize int) (chunks [][]string) {
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}
	return append(chunks, items)
}

func findCookie(cookies []*http.Cookie, name string) (string, error) {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value, nil
		}
	}
	return "", errors.New("cookie not found")
}

func getMacHWID() (string, error) {
	cmd := exec.Command("cmd", "/C", "wmic csproduct get UUID")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	output := out.String()
	re := regexp.MustCompile("[\r\n ]+")
	output = re.Split(output, -1)[1]
	return output, error(nil)
}
