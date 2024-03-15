package util

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	processStartTime int64 = time.Now().UnixNano() / 1e6
	seqId            int64 = 0
)

func ReadAsString(body io.Reader) (*string, error) {
	byt, err := ioutil.ReadAll(body)
	if err != nil {
		return String(""), err
	}
	r, ok := body.(io.ReadCloser)
	if ok {
		r.Close()
	}
	return String(string(byt)), nil
}

func StringifyMapValue(a map[string]interface{}) map[string]*string {
	res := make(map[string]*string)
	for key, value := range a {
		if value != nil {
			res[key] = ToJSONString(value)
		}
	}
	return res
}

func AnyifyMapValue(a map[string]*string) map[string]interface{} {
	res := make(map[string]interface{})
	for key, value := range a {
		res[key] = StringValue(value)
	}
	return res
}

func ReadAsBytes(body io.Reader) ([]byte, error) {
	byt, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, err
	}
	r, ok := body.(io.ReadCloser)
	if ok {
		r.Close()
	}
	return byt, nil
}

func DefaultString(reaStr, defaultStr *string) *string {
	if reaStr == nil {
		return defaultStr
	}
	return reaStr
}

func ToJSONString(a interface{}) *string {
	if a == nil {
		return String("")
	}
	switch v := a.(type) {
	case *string:
		return v
	case string:
		return String(v)
	case []byte:
		return String(string(v))
	case io.Reader:
		byt, err := io.ReadAll(v)
		if err != nil {
			return nil
		}
		return String(string(byt))
	}
	byt, err := json.Marshal(a)
	if err != nil {
		return nil
	}
	return String(string(byt))
}

func DefaultNumber(reaNum, defaultNum *int) *int {
	if reaNum == nil {
		return defaultNum
	}
	return reaNum
}

func ReadAsJSON(body io.Reader) (result interface{}, err error) {
	byt, err := io.ReadAll(body)
	if err != nil {
		return
	}
	if string(byt) == "" {
		return
	}
	r, ok := body.(io.ReadCloser)
	if ok {
		r.Close()
	}
	d := json.NewDecoder(bytes.NewReader(byt))
	d.UseNumber()
	err = d.Decode(&result)
	return
}

func Empty(val *string) *bool {
	return Bool(val == nil || StringValue(val) == "")
}

func EqualString(val1, val2 *string) *bool {
	return Bool(StringValue(val1) == StringValue(val2))
}

func EqualNumber(val1, val2 *int) *bool {
	return Bool(IntValue(val1) == IntValue(val2))
}

func IsUnset(val interface{}) *bool {
	if val == nil {
		return Bool(true)
	}

	v := reflect.ValueOf(val)
	if v.Kind() == reflect.Ptr || v.Kind() == reflect.Slice || v.Kind() == reflect.Map {
		return Bool(v.IsNil())
	}

	valType := reflect.TypeOf(val)
	valZero := reflect.Zero(valType)
	return Bool(valZero == v)
}

func ToBytes(a *string) []byte {
	return []byte(StringValue(a))
}

func AssertAsMap(a interface{}) (_result map[string]interface{}, _err error) {
	r := reflect.ValueOf(a)
	if r.Kind().String() != "map" {
		return nil, errors.New(fmt.Sprintf("%v is not a map[string]interface{}", a))
	}

	res := make(map[string]interface{})
	tmp := r.MapKeys()
	for _, key := range tmp {
		res[key.String()] = r.MapIndex(key).Interface()
	}

	return res, nil
}

func AssertAsNumber(a interface{}) (_result *int, _err error) {
	res := 0
	switch a.(type) {
	case int:
		tmp := a.(int)
		res = tmp
	case *int:
		tmp := a.(*int)
		res = IntValue(tmp)
	default:
		return nil, errors.New(fmt.Sprintf("%v is not a int", a))
	}

	return Int(res), nil
}

/**
 * Assert a value, if it is a integer, return it, otherwise throws
 * @return the integer value
 */
func AssertAsInteger(value interface{}) (_result *int, _err error) {
	res := 0
	switch value.(type) {
	case int:
		tmp := value.(int)
		res = tmp
	case *int:
		tmp := value.(*int)
		res = IntValue(tmp)
	default:
		return nil, errors.New(fmt.Sprintf("%v is not a int", value))
	}

	return Int(res), nil
}

func AssertAsBoolean(a interface{}) (_result *bool, _err error) {
	res := false
	switch a.(type) {
	case bool:
		tmp := a.(bool)
		res = tmp
	case *bool:
		tmp := a.(*bool)
		res = BoolValue(tmp)
	default:
		return nil, errors.New(fmt.Sprintf("%v is not a bool", a))
	}

	return Bool(res), nil
}

func AssertAsString(a interface{}) (_result *string, _err error) {
	res := ""
	switch a.(type) {
	case string:
		tmp := a.(string)
		res = tmp
	case *string:
		tmp := a.(*string)
		res = StringValue(tmp)
	default:
		return nil, errors.New(fmt.Sprintf("%v is not a string", a))
	}

	return String(res), nil
}

func AssertAsBytes(a interface{}) (_result []byte, _err error) {
	res, ok := a.([]byte)
	if !ok {
		return nil, errors.New(fmt.Sprintf("%v is not a []byte", a))
	}
	return res, nil
}

func AssertAsReadable(a interface{}) (_result io.Reader, _err error) {
	res, ok := a.(io.Reader)
	if !ok {
		return nil, errors.New(fmt.Sprintf("%v is not a reader", a))
	}
	return res, nil
}

func AssertAsArray(a interface{}) (_result []interface{}, _err error) {
	r := reflect.ValueOf(a)
	if r.Kind().String() != "array" && r.Kind().String() != "slice" {
		return nil, errors.New(fmt.Sprintf("%v is not a []interface{}", a))
	}
	aLen := r.Len()
	res := make([]interface{}, 0)
	for i := 0; i < aLen; i++ {
		res = append(res, r.Index(i).Interface())
	}
	return res, nil
}

func ParseJSON(a *string) interface{} {
	mapTmp := make(map[string]interface{})
	d := json.NewDecoder(bytes.NewReader([]byte(StringValue(a))))
	d.UseNumber()
	err := d.Decode(&mapTmp)
	if err == nil {
		return mapTmp
	}

	sliceTmp := make([]interface{}, 0)
	d = json.NewDecoder(bytes.NewReader([]byte(StringValue(a))))
	d.UseNumber()
	err = d.Decode(&sliceTmp)
	if err == nil {
		return sliceTmp
	}

	if num, err := strconv.Atoi(StringValue(a)); err == nil {
		return num
	}

	if ok, err := strconv.ParseBool(StringValue(a)); err == nil {
		return ok
	}

	if floa64tVal, err := strconv.ParseFloat(StringValue(a), 64); err == nil {
		return floa64tVal
	}
	return nil
}

func ToReader(obj interface{}) io.Reader {
	if obj == nil {
		return strings.NewReader("")
	}
	switch obj.(type) {
	case *string:
		tmp := obj.(*string)
		return strings.NewReader(StringValue(tmp))
	case []byte:
		return strings.NewReader(string(obj.([]byte)))
	case io.Reader:
		return obj.(io.Reader)
	default:
		panic("Invalid Body. Please set a valid Body.")
	}
}

func ToString(a []byte) *string {
	return String(string(a))
}

func ToMap(in interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}
	res := ToMap(in)
	return res
}

func ToFormString(a map[string]interface{}) *string {
	if a == nil {
		return String("")
	}
	res := ""
	urlEncoder := url.Values{}
	for key, value := range a {
		v := fmt.Sprintf("%v", value)
		urlEncoder.Add(key, v)
	}
	res = urlEncoder.Encode()
	return String(res)
}

func ToForm(filter map[string]interface{}) (_result *string) {
	tmp := make(map[string]interface{})
	byt, _ := json.Marshal(filter)
	d := json.NewDecoder(bytes.NewReader(byt))
	d.UseNumber()
	_ = d.Decode(&tmp)

	result := make(map[string]*string)
	for key, value := range tmp {
		filterValue := reflect.ValueOf(value)
		flatRepeatedList(filterValue, result, key)
	}

	m := AnyifyMapValue(result)
	return ToFormString(m)
}

func flatRepeatedList(dataValue reflect.Value, result map[string]*string, prefix string) {
	if !dataValue.IsValid() {
		return
	}

	dataType := dataValue.Type()
	if dataType.Kind().String() == "slice" {
		handleRepeatedParams(dataValue, result, prefix)
	} else if dataType.Kind().String() == "map" {
		handleMap(dataValue, result, prefix)
	} else {
		result[prefix] = String(fmt.Sprintf("%v", dataValue.Interface()))
	}
}

func handleRepeatedParams(repeatedFieldValue reflect.Value, result map[string]*string, prefix string) {
	if repeatedFieldValue.IsValid() && !repeatedFieldValue.IsNil() {
		for m := 0; m < repeatedFieldValue.Len(); m++ {
			elementValue := repeatedFieldValue.Index(m)
			key := prefix + "." + strconv.Itoa(m+1)
			fieldValue := reflect.ValueOf(elementValue.Interface())
			if fieldValue.Kind().String() == "map" {
				handleMap(fieldValue, result, key)
			} else {
				result[key] = String(fmt.Sprintf("%v", fieldValue.Interface()))
			}
		}
	}
}

func handleMap(valueField reflect.Value, result map[string]*string, prefix string) {
	if valueField.IsValid() && valueField.String() != "" {
		valueFieldType := valueField.Type()
		if valueFieldType.Kind().String() == "map" {
			var byt []byte
			byt, _ = json.Marshal(valueField.Interface())
			cache := make(map[string]interface{})
			d := json.NewDecoder(bytes.NewReader(byt))
			d.UseNumber()
			_ = d.Decode(&cache)
			for key, value := range cache {
				pre := ""
				if prefix != "" {
					pre = prefix + "." + key
				} else {
					pre = key
				}
				fieldValue := reflect.ValueOf(value)
				flatRepeatedList(fieldValue, result, pre)
			}
		}
	}
}

func GetDateUTCString() *string {
	return String(time.Now().UTC().Format(http.TimeFormat))
}

func Is2xx(code *int) *bool {
	tmp := IntValue(code)
	return Bool(tmp >= 200 && tmp < 300)
}

func Is3xx(code *int) *bool {
	tmp := IntValue(code)
	return Bool(tmp >= 300 && tmp < 400)
}

func Is4xx(code *int) *bool {
	tmp := IntValue(code)
	return Bool(tmp >= 400 && tmp < 500)
}

func Is5xx(code *int) *bool {
	tmp := IntValue(code)
	return Bool(tmp >= 500 && tmp < 600)
}

func ToArray(in interface{}) []map[string]interface{} {
	if BoolValue(IsUnset(in)) {
		return nil
	}

	tmp := make([]map[string]interface{}, 0)
	byt, _ := json.Marshal(in)
	d := json.NewDecoder(bytes.NewReader(byt))
	d.UseNumber()
	err := d.Decode(&tmp)
	if err != nil {
		return nil
	}
	return tmp
}

func Merge(args ...interface{}) map[string]*string {
	finalArg := make(map[string]*string)
	for _, obj := range args {
		switch obj.(type) {
		case map[string]*string:
			arg := obj.(map[string]*string)
			for key, value := range arg {
				if value != nil {
					finalArg[key] = value
				}
			}
		default:
			byt, _ := json.Marshal(obj)
			arg := make(map[string]string)
			err := json.Unmarshal(byt, &arg)
			if err != nil {
				return finalArg
			}
			for key, value := range arg {
				if value != "" {
					finalArg[key] = String(value)
				}
			}
		}
	}

	return finalArg
}

func HexEncode(raw []byte) *string {
	return String(hex.EncodeToString(raw))
}

func HexDecode(code string) ([]byte, error) {
	return hex.DecodeString(code)
}

func Base64Encode(raw []byte) *string {
	return String(base64.StdEncoding.EncodeToString(raw))
}

func Hash(raw []byte, signatureAlgorithm *string) []byte {
	signType := StringValue(signatureAlgorithm)
	if signType == SignatureAlgorithmHMACSHA256 {
		h := sha256.New()
		h.Write(raw)
		return h.Sum(nil)
	}
	return nil
}

func GetTimestamp() (_result *string) {
	gmt := time.FixedZone("GMT", 0)
	return String(time.Now().In(gmt).Format("2006-01-02T15:04:05Z"))
}

func getGID() uint64 {
	// https://blog.sgmansfield.com/2015/12/goroutine-ids/
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

func GetNonce() *string {
	routineId := getGID()
	currentTime := time.Now().UnixNano() / 1e6
	seq := atomic.AddInt64(&seqId, 1)
	randNum := rand.Int63()
	msg := fmt.Sprintf("%d-%d-%d-%d-%d", processStartTime, routineId, currentTime, seq, randNum)
	h := md5.New()
	h.Write([]byte(msg))
	ret := hex.EncodeToString(h.Sum(nil))
	return &ret
}
