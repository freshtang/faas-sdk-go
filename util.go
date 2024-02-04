package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

func StringPtr(a string) *string {
	return &a
}

func StringValue(a *string) string {
	if a == nil {
		return ""
	}
	return *a
}

func int32Ptr(a int32) *int32 {
	return &a
}

func toInt32(a int) *int32 {
	return int32Ptr(int32(a))
}

func ToReader(obj map[string]interface{}) io.Reader {
	if obj == nil {
		return nil
	}
	byt, _ := json.Marshal(obj)
	return strings.NewReader(string(byt))
}

func assertAsReadable(a interface{}) (_result io.Reader, _err error) {
	res, ok := a.(io.Reader)
	if !ok {
		return nil, errors.New(fmt.Sprintf("%v is not a reader", a))
	}
	return res, nil
}

func stringifyMapValue(a map[string][]string) map[string]*string {
	res := make(map[string]*string)
	for key, value := range a {
		if len(value) != 0 {
			res[strings.ToLower(key)] = StringPtr(value[0])
		}
	}
	return res
}

func toJSONString(a []string) *string {
	byt, err := json.Marshal(a)
	if err != nil {
		return nil
	}
	return StringPtr(string(byt))
}
