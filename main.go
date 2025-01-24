package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/urfave/cli/v3"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type Config struct {
	Url       string
	Username  string
	Password  string
	AuthType  string
	Verbose   bool
	Output    string
	ParsedUrl *url.URL
	Logger    *slog.Logger
}

func main() {
	var conf Config

	cmd := &cli.Command{
		Usage: "SUSE Observability Token fetcher.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "url",
				Usage:       "SUSE Observability URL",
				Destination: &conf.Url,
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "username",
				Aliases:     []string{"u"},
				Usage:       "Login user",
				Destination: &conf.Username,
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "password",
				Aliases:     []string{"p"},
				Usage:       "Login password. Can also be provided with env var 'SO_PASSWORD'",
				Destination: &conf.Password,
			},
			&cli.StringFlag{
				Name:        "auth-type",
				Aliases:     []string{"t"},
				Usage:       "Authentication type. Valid values 'default', 'keycloak'",
				Destination: &conf.AuthType,
				Value:       "default",
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "output",
				Aliases:     []string{"o"},
				Value:       "token.txt",
				Usage:       "Output file name that will contain CLI token",
				Destination: &conf.Output,
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Aliases:     []string{"v"},
				Destination: &conf.Verbose,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return action(&conf)
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func action(conf *Config) error {
	initLogger(conf)
	conf.Logger.Info("Validating required parameters")
	err := validate(conf)
	if err != nil {
		return err
	}

	token, err := fetchToken(conf)
	if err != nil {
		return err
	}

	conf.Logger.Info("Writing token", "token", token, "file", conf.Output)
	err = os.WriteFile(conf.Output, []byte(token), 0644)
	if err != nil {
		conf.Logger.Error("Writing token failed", "err", err)
		return err
	}
	return nil

}

func fetchToken(conf *Config) (string, error) {
	client, err := initClient()
	if err != nil {
		return "", err
	}
	switch conf.AuthType {
	case "keycloak":
		return fetchTokenUsingKeyCloakFlow(client, conf)
	default:
		return fetchTokenUsingDefaultFlow(client, conf)
	}
}

func fetchTokenUsingKeyCloakFlow(client *http.Client, conf *Config) (string, error) {
	conf.Logger.Info("Logging into keycloak")
	// Step 1: Initial GET request to trigger the redirect
	loginRedirectUrl := fmt.Sprintf("%s/api/server/webuiconfig", conf.Url)
	resp, err := client.Get(loginRedirectUrl)
	if err != nil {
		conf.Logger.Error("Error while trying to redirect to keycloak", "url", loginRedirectUrl, "err", err)
		return "", err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Step 2: Extract form action URL using regex
	re := regexp.MustCompile(`(?i)<form[^>]+action=["']?([^"' >]+)`)
	matches := re.FindSubmatch(body)
	if len(matches) < 2 {
		return "", errors.New("no form action found in page. contact developer for fix")
	}

	actionURL := string(matches[1])
	if !strings.HasPrefix(actionURL, "http") {
		actionURL = resp.Request.URL.Scheme + "://" + resp.Request.URL.Host + actionURL
	}

	// Step 3: Submit form data
	formData := url.Values{}
	formData.Set("username", conf.Username)
	formData.Set("password", conf.Password)
	formData.Set("credentialId", "")
	conf.Logger.Info("Posting login form", "url", actionURL)
	resp, err = client.PostForm(actionURL, formData)
	if err != nil {
		return "", err
	}

	// Check if final redirect landed back on original site
	if conf.ParsedUrl.Host != resp.Request.URL.Host {
		return "", errors.New("invalid username and password")
	}
	return fetchTokenFromEndpoint(client, conf)
}

func fetchTokenUsingDefaultFlow(client *http.Client, conf *Config) (string, error) {
	loginUrl := fmt.Sprintf("%s/loginCallback", conf.Url)
	formData := url.Values{}
	formData.Set("username", conf.Username)
	formData.Set("password", conf.Password)
	conf.Logger.Info("Posting login form", "url", loginUrl)
	resp, err := client.PostForm(loginUrl, formData)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", errors.New(fmt.Sprintf("unexpected status code: %d, url: %s", resp.StatusCode, loginUrl))
	}

	return fetchTokenFromEndpoint(client, conf)
}

func fetchTokenFromEndpoint(client *http.Client, conf *Config) (string, error) {
	tokenUrl := fmt.Sprintf("%s/api/user/profile/tokens", conf.Url)
	conf.Logger.Info("Fetching token from endpoint", "url", tokenUrl)
	tokenResp, err := client.Get(tokenUrl)
	if err != nil {
		return "", err
	}
	if tokenResp.StatusCode != 200 {
		return "", errors.New(fmt.Sprintf("unexpected status code: %d, url: %s", tokenResp.StatusCode, tokenUrl))
	}

	if tokenResp.Header.Get("Context-Type") == "text/html" {
		return "", errors.New("invalid username or password")
	}

	var data []map[string]interface{}
	err = json.NewDecoder(tokenResp.Body).Decode(&data)
	if err != nil {
		conf.Logger.Error("Error while trying unmarshall json", "err", err)
		return "", err
	}
	return data[0]["token"].(string), nil
}

func initClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Allow redirects
		},
	}
	return client, nil
}

func initLogger(conf *Config) {
	lvl := new(slog.LevelVar)
	if conf.Verbose {
		lvl.Set(slog.LevelInfo)
	} else {
		lvl.Set(slog.LevelError)
	}

	conf.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	}))
}

func validate(conf *Config) error {
	if conf.Password == "" {
		conf.Password = os.Getenv("SO_PASSWORD")
		if conf.Password == "" {
			return errors.New("password is required")
		}
	}

	if conf.AuthType != "default" && conf.AuthType != "keycloak" {
		if conf.AuthType == "" {
			conf.AuthType = "default"
		} else {
			return errors.New("auth type must be 'default' or 'keycloak'")
		}
	}

	if conf.Output == "" {
		conf.Output = "token.txt"
	}

	conf.Url = strings.TrimSuffix(conf.Url, "/")
	parsedUrl, err := url.Parse(conf.Url)
	if err != nil {
		return err
	}
	conf.ParsedUrl = parsedUrl
	return nil
}
