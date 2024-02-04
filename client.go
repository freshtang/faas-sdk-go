package client

import (
	"errors"

	"ctyun.dev/faas/pkg/credential/util"
)

// Endpoint规则：[product_code].[regionid].ctyun.cn
type Config struct {
	Endpoint  *string `json:"endpoint,omitempty" xml:"endpoint,omitempty"`
	AccessKey *string `json:"accessKey,omitempty" xml:"accessKey,omitempty"`
	SecretKey *string `json:"secretKey,omitempty" xml:"secretKey,omitempty"`
	Protocol  *string `json:"protocol,omitempty" xml:"protocol,omitempty"`
	Method    *string `json:"method,omitempty" xml:"method,omitempty"`
}

type client struct {
	Endpoint  *string
	AccessKey *string
	SecretKey *string
	Protocol  *string
	Method    *string
}

func NewClient(config *Config) (*client, error) {
	client := &client{}
	err := client.init(config)
	return client, err
}

func (c *client) init(config *Config) error {
	if config.Endpoint == nil {
		return errors.New("endpoint is required")
	}
	if config.AccessKey == nil || config.SecretKey == nil {
		return errors.New("aksk is required")
	}

	c.Endpoint = config.Endpoint
	c.AccessKey = config.AccessKey
	c.SecretKey = config.SecretKey
	c.Protocol = config.Protocol
	if config.Protocol == nil {
		c.Protocol = util.String("HTTPS")
	} else {
		c.Protocol = config.Protocol
	}
	c.Method = config.Method
	if config.Method == nil {
		c.Method = util.String("POST")
	} else {
		c.Method = config.Method
	}
	return nil
}
