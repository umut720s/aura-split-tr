package profile

import "encoding/base64"

func decodeKey(k string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(k)
}
