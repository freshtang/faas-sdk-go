package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gitlab.ctyun.cn/ctg-dcos/faas-sdk-go/credential"
	"gitlab.ctyun.cn/ctg-dcos/faas-sdk-go/credential/util"
)

const (
	InvokeFunctionPath = "/api/v1/functions/%s/invocations"
)

type InvokeFunctionHeaders struct {
	CommonHeaders     map[string]*string `json:"commonHeaders" xml:"commonHeaders"`
	XFcInvocationType *string            `json:"x-fc-invocation-type,omitempty" xml:"x-fc-invocation-type,omitempty"`
	XFcLogType        *string            `json:"x-fc-log-type,omitempty" xml:"x-fc-log-type,omitempty"`
}

func (s InvokeFunctionHeaders) String() string {
	resp, _ := json.MarshalIndent(s, "", "   ")
	return string(resp)
}

func (s InvokeFunctionHeaders) GoString() string {
	return s.String()
}

func (s *InvokeFunctionHeaders) SetCommonHeaders(v map[string]*string) *InvokeFunctionHeaders {
	s.CommonHeaders = v
	return s
}

func (s *InvokeFunctionHeaders) SetXFcInvocationType(v string) *InvokeFunctionHeaders {
	s.XFcInvocationType = &v
	return s
}

func (s *InvokeFunctionHeaders) SetXFcLogType(v string) *InvokeFunctionHeaders {
	s.XFcLogType = &v
	return s
}

type InvokeFunctionRequest struct {
	Body      io.Reader `json:"body,omitempty" xml:"body,omitempty"`
	Qualifier *string   `json:"qualifier,omitempty" xml:"qualifier,omitempty"`
}

func (s InvokeFunctionRequest) String() string {
	resp, _ := json.MarshalIndent(s, "", "   ")
	return string(resp)
}

func (s InvokeFunctionRequest) GoString() string {
	return s.String()
}

func (s *InvokeFunctionRequest) SetBody(v io.Reader) *InvokeFunctionRequest {
	s.Body = v
	return s
}

func (s *InvokeFunctionRequest) SetQualifier(v string) *InvokeFunctionRequest {
	s.Qualifier = &v
	return s
}

type InvokeFunctionResponse struct {
	Headers    map[string]*string `json:"headers" xml:"headers" require:"true"`
	StatusCode *int32             `json:"statusCode,omitempty" xml:"statusCode,omitempty" require:"true"`
	Body       io.Reader          `json:"body,omitempty" xml:"body,omitempty" require:"true"`
}

func (s InvokeFunctionResponse) String() string {
	resp, _ := json.MarshalIndent(s, "", "   ")
	return string(resp)
}

func (s InvokeFunctionResponse) GoString() string {
	return s.String()
}

func (s *InvokeFunctionResponse) SetHeaders(v map[string]*string) *InvokeFunctionResponse {
	s.Headers = v
	return s
}

func (s *InvokeFunctionResponse) SetStatusCode(v int32) *InvokeFunctionResponse {
	s.StatusCode = &v
	return s
}

func (s *InvokeFunctionResponse) SetBody(v io.Reader) *InvokeFunctionResponse {
	s.Body = v
	return s
}

/**
 * 调用函数。
 *
 * @param request InvokeFunctionRequest
 * @return InvokeFunctionResponse
 */
func (c *Client) InvokeFunction(functionName *string, request *InvokeFunctionRequest) (_result *InvokeFunctionResponse, _err error) {
	headers := &InvokeFunctionHeaders{}
	_result = &InvokeFunctionResponse{}
	_body, _err := c.InvokeFunctionWithOptions(functionName, request, headers)
	if _err != nil {
		return _result, _err
	}
	_result = _body
	return _result, _err
}

/**
 * 调用函数。
 *
 * @param request InvokeFunctionRequest
 * @param headers InvokeFunctionHeaders
 * @return InvokeFunctionResponse
 */
func (c *Client) InvokeFunctionWithOptions(functionName *string, request *InvokeFunctionRequest, headers *InvokeFunctionHeaders) (_result *InvokeFunctionResponse, _err error) {
	client := credential.NewCredential(c.AccessKey, c.SecretKey)
	query := make(map[string]*string)
	if request.Qualifier == nil {
		query["qualifier"] = StringPtr("latest")
	} else {
		query["qualifier"] = request.Qualifier
	}
	if request.Body == nil {
		request.Body = strings.NewReader("")
	}
	if headers.CommonHeaders == nil {
		headers.CommonHeaders = make(map[string]*string)
	}
	req := &credential.Request{
		Protocol:    c.Protocol,
		Method:      c.Method,
		Endpoint:    c.Endpoint,
		Path:        StringPtr(c.path(functionName)),
		ContentType: StringPtr("json"),
		Headers:     headers.CommonHeaders,
		Query:       query,
		Body:        request.Body,
	}
	rsp, err := client.DoRequest(req)
	if err != nil {
		return _result, err
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("response status code not equal to 200, code: %d\n", rsp.StatusCode))
	}
	defer rsp.Body.Close()

	// Read: HTTP结果
	res := &InvokeFunctionResponse{}
	rspBody, err := io.ReadAll(rsp.Body)
	if err != nil {
		return _result, err
	}
	res.Body = util.ToReader(rspBody)
	res.Headers = stringifyMapValue(rsp.Header)
	res.StatusCode = toInt32(rsp.StatusCode)
	_result = res
	return _result, _err
}

func (c *Client) path(functionName *string) string {
	return fmt.Sprintf(InvokeFunctionPath, *functionName)
}
