package main

import (
	"fmt"
	"os"

	client "gitlab.ctyun.cn/ctg-dcos/faas-sdk-go"
)

func main() {
	cfg := &client.Config{
		Endpoint:  client.StringPtr("cf.fc-gzsyj.ctyun.cn"),
		AccessKey: client.StringPtr(os.Getenv("CTYUN_ACCESS_KEY")),
		SecretKey: client.StringPtr(os.Getenv("CTYUN_SECRET_KEY")),
	}
	c, err := client.NewClient(cfg)
	request := &client.InvokeFunctionRequest{}
	header := &client.InvokeFunctionHeaders{}
	response, err := c.InvokeFunctionWithOptions(client.StringPtr("function_name"), request, header)
	if err != nil {
		panic(err)
	}
	fmt.Printf("response: %+v\n", response)
}
