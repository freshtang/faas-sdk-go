package credential

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"ctyun.dev/faas/pkg/credential/util"
	"github.com/google/uuid"
)

func (c *credential) DoCTAPIRequest(request *Request) (*http.Response, error) {
	// TODO(jiangkai): validate params
	// TODO(jiangkai): add retry logic
	resp, err := func() (*http.Response, error) {
		requestURL := fmt.Sprintf("%s://%s%s", util.StringValue(request.Protocol), util.StringValue(request.Endpoint), util.StringValue(request.Path))
		queryStr := getCTAPISortedQueryString(request.Query)
		if queryStr != "" {
			requestURL = requestURL + "?" + queryStr
		}
		reqBody := strings.NewReader("")
		if !util.BoolValue(util.IsUnset(request.Body)) {
			if util.BoolValue(util.EqualString(request.ContentType, util.String("json"))) {
				jsonObj := util.ToJSONString(request.Body)
				reqBody = strings.NewReader(*jsonObj)
				request.Headers["Content-Type"] = util.String("application/json; charset=utf-8")
			} else {
				m, err := util.AssertAsMap(request.Body)
				if err != nil {
					return nil, err
				}
				formObj := util.ToForm(m)
				reqBody = strings.NewReader(*formObj)
				request.Headers["Content-Type"] = util.String("application/x-www-form-urlencoded")
			}
		}
		httpReq, err := http.NewRequest(util.StringValue(request.Method), requestURL, reqBody)
		if err != nil {
			return nil, err
		}
		uuid := uuid.New().String()
		timestamp := time.Now()
		eopDate := timestamp.Format("20060102T150405Z")

		httpReq.Header.Add("Content-Type", util.StringValue(request.Headers["Content-Type"]))
		httpReq.Header.Add("ctyun-eop-request-id", uuid)
		httpReq.Header.Add("Eop-date", eopDate)
		httpReq.Header.Add("Eop-Authorization", getCTAPIAuthorization(queryStr, util.StringValue(util.ToJSONString(request.Body)), uuid, util.StringValue(c.AK), util.StringValue(c.SK), timestamp))
		for key, value := range request.Headers {
			if value != nil {
				httpReq.Header.Add(key, util.StringValue(value))
			}
		}
		// DO: HTTP请求
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		return client.Do(httpReq)
	}()
	return resp, err
}

func getCTAPISortedQueryString(query map[string]*string) string {
	queryArray := make([]string, 0)
	for key, value := range query {
		queryArray = append(queryArray, fmt.Sprintf("%s=%s", key, util.StringValue(value)))
	}
	sort.Slice(queryArray, func(i, j int) bool {
		return queryArray[i] < queryArray[j] // 正序
	})
	newQuery := ""
	for _, value := range queryArray {
		newQuery = newQuery + "&" + value
	}
	return encodeQueryStr(newQuery)
}

func encodeQueryStr(query string) string {
	afterQuery := ""
	if len(query) != 0 {
		n := strings.Split(query, "&")
		for _, v := range n {
			if len(afterQuery) < 1 {
				a := strings.Split(v, "=")
				if len(a) >= 2 {
					encodeStr := url.QueryEscape(a[1])
					v = a[0] + "=" + encodeStr
					afterQuery = afterQuery + v
				} else {
					encodeStr := ""
					v = a[0] + "=" + encodeStr
					afterQuery = afterQuery + v
				}
			} else {
				a := strings.Split(v, "=")
				if len(a) >= 2 {
					encodeStr := url.QueryEscape(a[1])
					v = a[0] + "=" + encodeStr
					afterQuery = afterQuery + "&" + v
				} else {
					encodeStr := ""
					v = a[0] + "=" + encodeStr
					afterQuery = afterQuery + "&" + v
				}
			}
		}
	}

	return afterQuery
}

func getCTAPIAuthorization(query, body, uuid, ak, sk string, timestamp time.Time) string {
	hashedRequestBody := util.StringValue(util.HexEncode(util.Hash([]byte(body), util.String(util.DefaultSignatureAlgorithm))))
	var sigture string
	singerDate := timestamp.Format("20060102T150405Z")
	singerDd := timestamp.Format("20060102")
	CampmocalHeader := "ctyun-eop-request-id:" + uuid + "\neop-date:" + singerDate + "\n"
	if query == "=&=" {
		sigture = CampmocalHeader + "\n" + "" + "\n" + hashedRequestBody
	} else {
		sigture = CampmocalHeader + "\n" + query + "\n" + hashedRequestBody
	}
	ktime := signatureMethod(sk, singerDate, util.DefaultSignatureAlgorithm)
	kak := signatureMethod(string(ktime), ak, util.DefaultSignatureAlgorithm)
	kdate := signatureMethod(string(kak), singerDd, util.DefaultSignatureAlgorithm)
	signaSha256 := signatureMethod(string(kdate), sigture, util.DefaultSignatureAlgorithm)
	signHeader := ak + " Headers=ctyun-eop-request-id;eop-date Signature=" + util.StringValue(util.Base64Encode(signaSha256))
	return signHeader
}
