// For CTYun FaaS SDK Signature
package credential

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"
	"time"

	"ctyun.dev/faas/pkg/credential/util"
)

type Request struct {
	Action      *string            `json:"action,omitempty" xml:"action,omitempty" require:"true"`
	Version     *string            `json:"version,omitempty" xml:"version,omitempty" require:"true"`
	Protocol    *string            `json:"protocol,omitempty" xml:"protocol,omitempty" require:"true"`
	Method      *string            `json:"method,omitempty" xml:"method,omitempty" require:"true"`
	Endpoint    *string            `json:"endpoint,omitempty" xml:"endpoint,omitempty" require:"true"`
	Path        *string            `json:"pathname,omitempty" xml:"pathname,omitempty" require:"true"`
	ContentType *string            `json:"reqBodyType,omitempty" xml:"reqBodyType,omitempty" require:"true"`
	Headers     map[string]*string `json:"headers,omitempty" xml:"headers,omitempty"`
	Query       map[string]*string `json:"query,omitempty" xml:"query,omitempty"`
	Body        interface{}        `json:"body,omitempty" xml:"body,omitempty"`
}

type credential struct {
	AK *string
	SK *string
}

type Credential interface {
	GetAccessKey() *string
	GetSecretKey() *string
	DoRequest(request *Request) (*http.Response, error)
	DoCTAPIRequest(request *Request) (*http.Response, error)
	ValidateSignature(request *http.Request) (bool, error)
	ValidateCTAPISignature(request *http.Request) (bool, error)
}

func NewCredential(ak *string, sk *string) Credential {
	if ak == nil || sk == nil {
		panic("key is empty")
	}
	return &credential{
		AK: ak,
		SK: sk,
	}
}

func (c *credential) GetAccessKey() *string {
	return c.AK
}

func (c *credential) GetSecretKey() *string {
	return c.SK
}

func (c *credential) DoRequest(request *Request) (*http.Response, error) {
	// TODO(jiangkai): validate params
	// TODO(jiangkai): add retry logic
	resp, err := func() (*http.Response, error) {
		signatureAlgorithm := util.String(util.DefaultSignatureAlgorithm)
		hashedRequestPayload := util.HexEncode(util.Hash(util.ToBytes(util.String("")), signatureAlgorithm))
		if !util.BoolValue(util.IsUnset(request.Body)) {
			if util.BoolValue(util.EqualString(request.ContentType, util.String("json"))) {
				jsonObj := util.ToJSONString(request.Body)
				hashedRequestPayload = util.HexEncode(util.Hash(util.ToBytes(jsonObj), signatureAlgorithm))
				request.Body = strings.NewReader(*jsonObj)
				request.Headers["content-type"] = util.String("application/json; charset=utf-8")
			} else if util.BoolValue(util.EqualString(request.ContentType, util.String("cloudevents+json"))) {
				jsonObj := util.ToJSONString(request.Body)
				hashedRequestPayload = util.HexEncode(util.Hash(util.ToBytes(jsonObj), signatureAlgorithm))
				request.Body = strings.NewReader(*jsonObj)
				request.Headers["content-type"] = util.String("application/cloudevents+json; charset=utf-8")
			} else {
				m, err := util.AssertAsMap(request.Body)
				if err != nil {
					return nil, err
				}
				formObj := util.ToForm(m)
				hashedRequestPayload = util.HexEncode(util.Hash(util.ToBytes(formObj), signatureAlgorithm))
				request.Body = strings.NewReader(*formObj)
				request.Headers["content-type"] = util.String("application/x-www-form-urlencoded")
			}
		}

		request.Headers["host"] = request.Endpoint
		if request.Action != nil {
			request.Headers["x-eop-action"] = request.Action
		}
		if request.Version != nil {
			request.Headers["x-eop-version"] = request.Version
		}
		request.Headers["x-eop-date"] = util.GetTimestamp()
		request.Headers["x-eop-signature-nonce"] = util.GetNonce()
		request.Headers["x-eop-content-sha256"] = hashedRequestPayload
		request.Headers["Authorization"] = GetAuthorization(request, signatureAlgorithm, hashedRequestPayload, c.AK, c.SK)
		return c.doRequest(request)
	}()
	return resp, err
}

func (c *credential) ValidateSignature(request *http.Request) (bool, error) {
	ctxAuth := request.Header.Get("Authorization")
	ctxAK := strings.Split(strings.Split(ctxAuth, ",")[0], "Credential=")[1]
	if !util.BoolValue(util.EqualString(c.AK, util.String(ctxAK))) {
		return false, nil
	}

	signatureAlgorithm := util.String(util.DefaultSignatureAlgorithm)
	hashedRequestPayload := util.HexEncode(util.Hash(util.ToBytes(util.String("")), signatureAlgorithm))
	if !util.BoolValue(util.IsUnset(request.Body)) {
		if strings.Contains(request.Header.Get("Content-Type"), "application/json") {
			jsonObj := util.ToJSONString(request.Body)
			hashedRequestPayload = util.HexEncode(util.Hash(util.ToBytes(jsonObj), signatureAlgorithm))
		} else {
			m, err := util.AssertAsMap(request.Body)
			if err != nil {
				return false, err
			}
			formObj := util.ToForm(m)
			hashedRequestPayload = util.HexEncode(util.Hash(util.ToBytes(formObj), signatureAlgorithm))
		}
	}

	req := &Request{
		Method:  util.String(request.Method),
		Path:    util.String(request.URL.Path),
		Headers: toRequestHeader(request),
		Query:   toRequestQuery(request),
	}
	encodeSignature := util.StringValue(GetAuthorization(req, signatureAlgorithm, hashedRequestPayload, c.AK, c.SK))
	return strings.Split(ctxAuth, "Signature=")[1] == strings.Split(encodeSignature, "Signature=")[1], nil
}

func (c *credential) ValidateCTAPISignature(request *http.Request) (bool, error) {
	ctxAuth := request.Header.Get("Eop-Authorization")
	ctxAK := strings.Split(ctxAuth, " ")[0]
	if !util.BoolValue(util.EqualString(c.AK, util.String(ctxAK))) {
		return false, nil
	}

	uid := request.Header.Get("ctyun-eop-request-id")
	eopDate := request.Header.Get("Eop-date")
	t, err := time.Parse(util.TimeFormat, eopDate)
	if err != nil {
		return false, err
	}
	queryStr := getCTAPISortedQueryString(toRequestQuery(request))
	bodyStr := util.StringValue(util.ToJSONString(request.Body))
	authorization := getCTAPIAuthorization(queryStr, bodyStr, uid, util.StringValue(c.AK), util.StringValue(c.SK), t)
	signature := strings.Split(authorization, "Signature=")[1] // 解密: base64.StdEncoding.EncodeToString([]byte(Signature))
	return strings.Split(ctxAuth, "Signature=")[1] == signature, nil
}

func (c *credential) doRequest(request *Request) (*http.Response, error) {
	if request.Method == nil {
		request.Method = util.String("GET")
	}
	if request.Protocol == nil {
		request.Protocol = util.String("http")
	} else {
		request.Protocol = util.String(strings.ToLower(util.StringValue(request.Protocol)))
	}

	requestURL := fmt.Sprintf("%s://%s%s", util.StringValue(request.Protocol), util.StringValue(request.Endpoint), util.StringValue(request.Path))
	queryStr := GetSortedQueryString(request.Query)
	if len(queryStr) > 0 {
		if strings.Contains(requestURL, "?") {
			requestURL = fmt.Sprintf("%s&%s", requestURL, queryStr)
		} else {
			requestURL = fmt.Sprintf("%s?%s", requestURL, queryStr)
		}
	}

	httpRequest, err := http.NewRequest(util.StringValue(request.Method), requestURL, util.ToReader(request.Body))
	if err != nil {
		return nil, err
	}
	httpRequest.Host = util.StringValue(request.Endpoint)
	for key, value := range request.Headers {
		if value == nil || key == "content-length" {
			continue
		} else if key == "host" {
			httpRequest.Header["Host"] = []string{*value}
			delete(httpRequest.Header, "host")
		} else if key == "user-agent" {
			httpRequest.Header["User-Agent"] = []string{*value}
			delete(httpRequest.Header, "user-agent")
		} else {
			httpRequest.Header[key] = []string{*value}
		}
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	return client.Do(httpRequest)
}

func toRequestContentType(request *http.Request) *string {
	if strings.Contains(request.Header.Get("Content-Type"), "application/json") {
		return util.String("json")
	}
	// TODO(jiangkai): 支持其他ContentType
	return nil
}

func toRequestHeader(request *http.Request) map[string]*string {
	result := make(map[string]*string)
	for key, value := range request.Header {
		if len(value) != 0 {
			result[strings.ToLower(key)] = util.String(value[0])
		}
	}
	return result
}

func toRequestQuery(request *http.Request) map[string]*string {
	result := make(map[string]*string)
	for key, value := range request.URL.Query() {
		if len(value) != 0 {
			result[strings.ToLower(key)] = util.String(value[0])
		}
	}
	return result
}

func GetAuthorization(request *Request, signatureAlgorithm, payload, ak, sk *string) *string {
	canonicalURI := util.StringValue(request.Path)
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalURI = strings.Replace(canonicalURI, "+", "%20", -1)
	canonicalURI = strings.Replace(canonicalURI, "*", "%2A", -1)
	canonicalURI = strings.Replace(canonicalURI, "%7E", "~", -1)

	method := util.StringValue(request.Method)
	canonicalQueryString := getCanonicalQueryString(request.Query)
	canonicalheaders, signedHeaders := getCanonicalHeaders(request.Headers)

	canonicalRequest := method + "\n" + canonicalURI + "\n" + canonicalQueryString + "\n" + canonicalheaders + "\n" +
		strings.Join(signedHeaders, ";") + "\n" + util.StringValue(payload)
	signType := util.StringValue(signatureAlgorithm)
	StringToSign := signType + "\n" + util.StringValue(util.HexEncode(util.Hash([]byte(canonicalRequest), signatureAlgorithm)))
	signature := util.StringValue(util.HexEncode(signatureMethod(util.StringValue(sk), StringToSign, signType)))
	auth := signType + " Credential=" + util.StringValue(ak) + ",SignedHeaders=" +
		strings.Join(signedHeaders, ";") + ",Signature=" + signature
	return util.String(auth)
}

func getCanonicalQueryString(query map[string]*string) string {
	canonicalQueryString := ""
	if util.BoolValue(util.IsUnset(query)) {
		return canonicalQueryString
	}
	tmp := make(map[string]string)
	for k, v := range query {
		tmp[k] = util.StringValue(v)
	}

	hs := util.NewSorter(tmp)

	// Sort the temp by the ascending order
	hs.Sort()
	for i := range hs.Keys {
		if hs.Vals[i] != "" {
			canonicalQueryString += "&" + hs.Keys[i] + "=" + url.QueryEscape(hs.Vals[i])
		} else {
			canonicalQueryString += "&" + hs.Keys[i] + "="
		}
	}
	canonicalQueryString = strings.Replace(canonicalQueryString, "+", "%20", -1)
	canonicalQueryString = strings.Replace(canonicalQueryString, "*", "%2A", -1)
	canonicalQueryString = strings.Replace(canonicalQueryString, "%7E", "~", -1)

	if canonicalQueryString != "" {
		canonicalQueryString = strings.TrimLeft(canonicalQueryString, "&")
	}
	return canonicalQueryString
}

func getCanonicalHeaders(headers map[string]*string) (string, []string) {
	tmp := make(map[string]string)
	tmpHeader := http.Header{}
	for k, v := range headers {
		if strings.HasPrefix(strings.ToLower(k), "x-eop-") || strings.ToLower(k) == "host" ||
			strings.ToLower(k) == "content-type" {
			tmp[strings.ToLower(k)] = strings.TrimSpace(util.StringValue(v))
			tmpHeader.Add(strings.ToLower(k), strings.TrimSpace(util.StringValue(v)))
		}
	}
	hs := util.NewSorter(tmp)

	// Sort the temp by the ascending order
	hs.Sort()
	canonicalheaders := ""
	for _, key := range hs.Keys {
		vals := tmpHeader[textproto.CanonicalMIMEHeaderKey(key)]
		sort.Strings(vals)
		canonicalheaders += key + ":" + strings.Join(vals, ",") + "\n"
	}

	return canonicalheaders, hs.Keys
}

func signatureMethod(secret, source, signatureAlgorithm string) []byte {
	if signatureAlgorithm == util.SignatureAlgorithmHMACSHA256 {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(source))
		return h.Sum(nil)
	}
	return nil
}

func GetSortedQueryString(query map[string]*string) string {
	q := url.Values{}
	for key, value := range query {
		q.Add(key, util.StringValue(value))
	}
	return q.Encode()
}
