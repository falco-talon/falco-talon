package http

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

var httpClient *http.Client
var once sync.Once

const (
	DefaultTimeout     = 10
	InsecureSkipVerify = false
)

func Init() error {
	if httpClient != nil {
		return nil
	}

	once.Do(func() {
		timeout := time.Duration(DefaultTimeout) * time.Second // Default timeout
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: InsecureSkipVerify},
			},
			Timeout: timeout,
		}
	})
	return nil
}

func GetClient() *http.Client {
	return httpClient
}

func OverrideClientSettings(client *http.Client, skipTLS bool, timeout int) {
	if timeout > 0 {
		client.Timeout = time.Duration(timeout) * time.Second
	}

	if skipTLS {
		updateInsecureSkipVerify(client, skipTLS)
	}
}

func updateInsecureSkipVerify(client *http.Client, skipVerify bool) {
	if client != nil && client.Transport != nil {
		oldTransport := client.Transport.(*http.Transport)
		newTransport := oldTransport.Clone()
		newTransport.TLSClientConfig.InsecureSkipVerify = skipVerify
		client.Transport = newTransport
	}
}
