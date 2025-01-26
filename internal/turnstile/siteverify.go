package turnstile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

type response struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

type Turnstile struct {
	secretKey string
	client    *http.Client
}

const BASE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

func New(secretKey string) *Turnstile {
	return &Turnstile{secretKey, &http.Client{}}
}

func (t *Turnstile) Verify(ctx context.Context, token string, remoteip ...string) error {
	// Prepare the request
	req, err := t.generateRequest(ctx, token, remoteip...)
	if err != nil {
		return err
	}

	// send the request
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check errors
	if resp.StatusCode >= 400 {
		return fmt.Errorf("error: HTTP %d", resp.StatusCode)
	}

	// read body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// parse
	var result response
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}

	// check failure
	if !result.Success {
		errCodes := strings.Join(result.ErrorCodes, ", ")
		return fmt.Errorf("verification failed with error codes: %s", errCodes)
	}

	// all ok!
	return nil
}

func (t Turnstile) generateRequest(ctx context.Context, token string, remoteip ...string) (*http.Request, error) {
	formData := url.Values{}
	formData.Set("secret", t.secretKey)
	formData.Set("response", token)
	formData.Set("idempotency_key", uuid.New().String())
	if len(remoteip) > 0 {
		formData.Set("remoteip", remoteip[0])
	}

	encodedData := formData.Encode()

	req, err := http.NewRequestWithContext(ctx, "POST", BASE_URL, strings.NewReader(encodedData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}
