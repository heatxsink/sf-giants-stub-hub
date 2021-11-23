package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kr/pretty"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	eventIDOption         string
	consumerKeyOption     string
	consumerSecretOption  string
	usernameOption        string
	passwordOption        string
	loggingFilenameOption string
	slogger               *zap.SugaredLogger
)

type GenerateToken struct {
	RefreshTokenExpiresIn string   `json:"refresh_token_expires_in"`
	TokenType             string   `json:"token_type"`
	IssuedAt              string   `json:"issued_at"`
	ClientID              string   `json:"client_id"`
	ApplicationName       string   `json:"application_name"`
	Scope                 string   `json:"scope"`
	RefreshTokenIssuedAt  string   `json:"refresh_token_issued_at"`
	ExpiresIn             string   `json:"expires_in"`
	RefreshCount          string   `json:"refresh_count"`
	RefreshTokenStatus    string   `json:"refresh_token_status"`
	APIProductList        string   `json:"api_product_list"`
	APIProductListJSON    []string `json:"api_product_list_json"`
	OrganizationName      string   `json:"organization_name"`
	DeveloperEmail        string   `json:"developer.email"`
	AccessToken           string   `json:"access_token"`
	RefreshToken          string   `json:"refresh_token"`
	Status                string   `json:"status"`
	UserGUID              string   `json:"user_guid"`
}

type SearchEvent struct {
	Numfound int `json:"numFound"`
	Events   []struct {
		ID              int    `json:"id"`
		Status          string `json:"status"`
		Locale          string `json:"locale"`
		Name            string `json:"name"`
		Description     string `json:"description"`
		Weburi          string `json:"webURI"`
		Eventdatelocal  string `json:"eventDateLocal"`
		Eventdateutc    string `json:"eventDateUTC"`
		Createddate     string `json:"createdDate"`
		Lastupdateddate string `json:"lastUpdatedDate"`
		Hideeventdate   bool   `json:"hideEventDate"`
		Hideeventtime   bool   `json:"hideEventTime"`
		Venue           struct {
			ID              int     `json:"id"`
			Name            string  `json:"name"`
			City            string  `json:"city"`
			State           string  `json:"state"`
			Postalcode      string  `json:"postalCode"`
			Country         string  `json:"country"`
			Venueconfigid   int     `json:"venueConfigId"`
			Venueconfigname string  `json:"venueConfigName"`
			Latitude        float64 `json:"latitude"`
			Longitude       float64 `json:"longitude"`
		} `json:"venue"`
		Timezone   string `json:"timezone"`
		Performers []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			Role string `json:"role,omitempty"`
		} `json:"performers"`
		Ancestors struct {
			Categories []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"categories"`
			Groupings []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"groupings"`
			Performers []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"performers"`
		} `json:"ancestors"`
		Categoriescollection struct {
			Categories []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"categories"`
		} `json:"categoriesCollection"`
		Currencycode string `json:"currencyCode"`
		Ticketinfo   struct {
			Minprice      float64 `json:"minPrice"`
			Minlistprice  float64 `json:"minListPrice"`
			Maxlistprice  float64 `json:"maxListPrice"`
			Totaltickets  float64 `json:"totalTickets"`
			Totallistings float64 `json:"totalListings"`
		} `json:"ticketInfo"`
	} `json:"events"`
}

func initLogger(filename string) *zap.SugaredLogger {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   filename,
		MaxSize:    100, //mb
		MaxBackups: 10,
		MaxAge:     30, //days
		Compress:   false,
	}
	writerSyncer := zapcore.AddSync(lumberJackLogger)
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoder := zapcore.NewConsoleEncoder(encoderConfig)
	core := zapcore.NewCore(encoder, writerSyncer, zapcore.DebugLevel)
	logger := zap.New(core, zap.AddCaller())
	return logger.Sugar()
}

func httpPost(ctx context.Context, url string, headers map[string]string, body string) (*http.Response, error) {
	r, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %v", err)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(body)))
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	client := &http.Client{
		Timeout:   time.Second * 10,
		Transport: transport,
	}
	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func httpGet(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %v", err)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	client := &http.Client{
		Timeout:   time.Second * 10,
		Transport: transport,
	}
	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func generateToken(ctx context.Context, consumerKey, consumerSecret, username, password string) (*GenerateToken, error) {
	data := fmt.Sprintf("%s:%s", consumerKey, consumerSecret)
	auth := base64.StdEncoding.EncodeToString([]byte(data))
	url := "https://api.stubhub.com/sellers/oauth/accesstoken?grant_type=client_credentials"
	body := fmt.Sprintf("{\"username\":\"%s\",\"password\": \"%s\"}", username, password)
	headers := make(map[string]string)
	headers["Authorization"] = fmt.Sprintf("Basic %s", auth)
	r, err := httpPost(ctx, url, headers, body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var gt GenerateToken
	err = json.Unmarshal(bodyBytes, &gt)
	if err != nil {
		return nil, err
	}
	return &gt, nil
}

func searchEvent(ctx context.Context, eventID, start, rows, accessToken string) (*SearchEvent, error) {
	url := fmt.Sprintf("https://api.stubhub.com/sellers/search/events/v3?id=%s&start=%s&rows=%s", eventID, rows, start)
	headers := make(map[string]string)
	headers["Authorization"] = fmt.Sprintf("Bearer %s", accessToken)
	headers["Accept"] = "application/json"
	r, err := httpGet(ctx, url, headers)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var se SearchEvent
	err = json.Unmarshal(bodyBytes, &se)
	if err != nil {
		return nil, err
	}
	return &se, nil
}

func findListings(ctx context.Context, eventID, sort, start, rows, priceMin, priceMax, accessToken string) error {
	url := fmt.Sprintf("https://api.stubhub.com/sellers/find/listings/v3/?eventId=%s&sort=%s&start=%s&rows=%s&priceMin=%s&priceMax=%s", eventID, sort, start, rows, priceMin, priceMax)
	headers := make(map[string]string)
	headers["Authorization"] = fmt.Sprintf("Bearer %s", accessToken)
	headers["Accept"] = "application/json"
	r, err := httpGet(ctx, url, headers)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(bodyBytes))
	return nil
}

func main() {
	rootCmd := &cobra.Command{
		Use: "sf-giants-stub-hub",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			gt, err := generateToken(ctx, consumerKeyOption, consumerSecretOption, usernameOption, passwordOption)
			if err != nil {
				return err
			}
			se, err := searchEvent(ctx, eventIDOption, "0", "10", gt.AccessToken)
			if err != nil {
				return err
			}
			for _, e := range se.Events {
				slogger.Infof("%# v\n", pretty.Formatter(e.Ticketinfo))
				slogger.Info("eventID: ", e.ID)
			}
			err = findListings(ctx, eventIDOption, "currentprice%3Dasc", "0", "50", "50", "300", gt.AccessToken)
			if err != nil {
				return err
			}
			return nil
		},
	}
	rootCmd.PersistentFlags().StringVarP(&eventIDOption, "event-id", "e", "", "StubHub API Event ID")
	rootCmd.PersistentFlags().StringVarP(&consumerKeyOption, "key", "k", "", "StubHub API Consumer Key")
	rootCmd.PersistentFlags().StringVarP(&consumerSecretOption, "secret", "s", "", "StubHub API Consumer Secret")
	rootCmd.PersistentFlags().StringVarP(&usernameOption, "username", "u", "", "StubHub Account Username")
	rootCmd.PersistentFlags().StringVarP(&passwordOption, "password", "p", "", "StubHub Account Password")
	rootCmd.PersistentFlags().StringVarP(&loggingFilenameOption, "log", "l", "./logs/sf-giants-stub-hub.log", "log filename")
	rootCmd.MarkFlagRequired("event-id")
	rootCmd.MarkFlagRequired("key")
	rootCmd.MarkFlagRequired("secret")
	rootCmd.MarkFlagRequired("username")
	rootCmd.MarkFlagRequired("password")
	rootCmd.MarkFlagRequired("log")
	rootCmd.Execute()
	slogger = initLogger(loggingFilenameOption)
	defer slogger.Sync()
}
