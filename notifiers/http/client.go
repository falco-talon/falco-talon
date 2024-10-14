package http

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"

	"github.com/falcosecurity/falco-talon/utils"
)

var ErrHeaderMissing = errors.New("header missing")                   // ErrHeaderMissing = 400
var ErrClientAuthenticationError = errors.New("authentication error") // ErrClientAuthenticationError = 401
var ErrForbidden = errors.New("access denied")                        // ErrForbidden = 403
var ErrNotFound = errors.New("resource not found")                    // ErrNotFound = 404
var ErrUnprocessableEntityError = errors.New("wrong request")         // ErrUnprocessableEntityError = 422
var ErrTooManyRequest = errors.New("exceeding post rate limit")       // ErrTooManyRequest = 429

const DefaultContentType = "application/json; charset=utf-8"
const DefaultHTTPMethod = "POST"
const DefaultUserAgent = "falco-talon"

type Client struct {
	Headers    http.Header
	HTTPMethod string
	Compressed bool
}

func CheckURL(u string) error {
	reg := regexp.MustCompile(`(http)(s?)://.*`)
	if !reg.MatchString(u) {
		return errors.New("invalid url")
	}

	if _, err := url.ParseRequestURI(u); err != nil {
		return errors.New("invalid url")
	}

	_, err := url.Parse(u)
	if err != nil {
		return err
	}

	return nil
}

func DefaultClient() Client {
	h := http.Header{}
	h.Set("Content-Type", DefaultContentType)
	return Client{
		HTTPMethod: "POST",
		Headers:    h,
	}
}

func (c *Client) SetHTTPMethod(hm string) {
	c.HTTPMethod = hm
}

func (c *Client) SetContentType(ct string) {
	c.Headers.Set("Content-Type", ct)
}

func (c *Client) SetBasicAuth(user, password string) {
	c.Headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
}

func (c *Client) SetHeader(key, value string) {
	c.Headers.Set(key, value)
}

func (c *Client) DeleteHeader(key string) {
	c.Headers.Del(key)
}

func NewClient(httpMethod, contentType, userAgent string, headers map[string]string) Client {
	h := http.Header{}
	if len(headers) != 0 {
		for i, j := range headers {
			h.Add(i, j)
		}
	}

	m := DefaultHTTPMethod
	if httpMethod != "" {
		m = httpMethod
	}

	a := DefaultUserAgent
	if userAgent != "" {
		a = userAgent
	}
	h.Set("User-Agent", a)

	ct := DefaultContentType
	if contentType != "" {
		ct = contentType
	}
	h.Set("Content-Type", ct)

	return Client{
		HTTPMethod: m,
		Headers:    h,
	}
}

func (c *Client) Request(u string, payload any) error {
	// defer + recover to catch panic if output doesn't respond
	defer func() {
		if err := recover(); err != nil {
			utils.PrintLog("error", utils.LogLine{Error: "recover"})
		}
	}()

	body := new(bytes.Buffer)

	if c.HTTPMethod != "GET" {
		if err := json.NewEncoder(body).Encode(payload); err != nil {
			return err
		}
	}

	client := &http.Client{
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
	}

	req, err := http.NewRequest(c.HTTPMethod, u, body)
	if err != nil {
		return err
	}

	req.Header = c.Headers

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent: // 200, 201, 202, 204
		return nil
	case http.StatusBadRequest: // 400
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return ErrHeaderMissing
		}
		return fmt.Errorf("%v: %v", ErrHeaderMissing, string(bodyBytes))
	case http.StatusUnauthorized: // 401
		return ErrClientAuthenticationError
	case http.StatusForbidden: // 403
		return ErrForbidden
	case http.StatusNotFound: // 404
		return ErrNotFound
	case http.StatusUnprocessableEntity: // 422
		return ErrUnprocessableEntityError
	case http.StatusTooManyRequests: // 429
		return ErrTooManyRequest
	default:
		return errors.New(resp.Status)
	}
}
