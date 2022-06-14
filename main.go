package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sync/errgroup"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	configFilepath string
	cfg            *config
)

/**
 * config structs
 */

type config struct {
	/** global config **/
	Port        int    `json:"port,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Issuer      string `json:"issuer,omitempty"`

	Users map[string]string `json:"users,omitempty"`
	Repos map[string]*repo  `json:"repos,omitempty"`
}
type repo struct {
	Read  []string `ini:"read"`
	Write []string `ini:"write"`
}

/**
 * internal structs
 */

type tokenPayload struct {
	// Iss token签发组织
	Iss string `json:"iss,omitempty"`
	// Aud 哪个服务可用
	Aud string `json:"aud,omitempty"`
	// Sub token使用用户名
	Sub string `json:"sub,omitempty"`

	// Iat token签发时间
	Iat *int `json:"iat,omitempty"`
	// Exp token过期时间
	Exp *int `json:"exp,omitempty"`
	// Nbf Not Before token在此之前不可用
	Nbf *int `json:"nbf,omitempty"`

	Access []access `json:"access,omitempty"`
}

func (payload *tokenPayload) AppendAccess(access access) {
	payload.Access = append(payload.Access, access)
}

func (payload *tokenPayload) Json() string {
	encode, _ := json.Marshal(payload)

	return string(encode)
}

type tokenHeader struct {
	Alg string   `json:"alg,omitempty"`
	Typ string   `json:"typ,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

func (tokenHeader *tokenHeader) Json() string {
	encode, _ := json.Marshal(tokenHeader)
	return string(encode)
}

type access struct {
	Type    string   `json:"type,omitempty"`
	Name    string   `json:"name,omitempty"`
	Actions []string `json:"actions,omitempty"`
}

func (access *access) Enable(act string) {
	access.Actions = append(access.Actions, act)
}

func GenerateToken(header *tokenHeader, payload *tokenPayload) (string, error) {

	block, _ := pem.Decode([]byte(cfg.PrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	// payload
	now := int(time.Now().Unix())
	exp := int(time.Now().Unix() + 600)

	payload.Iss = cfg.Issuer
	payload.Iat = &now
	payload.Nbf = &now
	payload.Exp = &exp

	payloadEncode := payload.Json()

	// header
	headerEncode := header.Json()

	signPayload := fmt.Sprintf("%s.%s", safeEncode([]byte(headerEncode)), safeEncode([]byte(payloadEncode)))

	hashed := sha512.Sum512([]byte(signPayload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, hashed[:])
	if err != nil {
		return "", err
	}

	token := fmt.Sprintf("%s.%s", signPayload, safeEncode(signature))

	return token, nil
}

func main() {

	var errg errgroup.Group
	var err error

	// 解析参数
	flag.StringVar(&configFilepath, "config", "./config.json", "config file path")
	flag.Parse()

	cfg, err = parseConfig(configFilepath)
	if err != nil {
		log.Fatalln(err)
	}

	// 注册网络监听
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("INFO server started with : %s \n", ln.Addr())

	// 注册HTTP回调
	http.HandleFunc("/", authHandler)

	// 运行HTTP服务
	errg.Go(func() error {
		return http.Serve(ln, nil)
	})

	log.Fatalln(errg.Wait())
}

func authHandler(writer http.ResponseWriter, request *http.Request) {
	defer func() {
		err := recover()
		if err != nil {
			log.Println("WARN", err)
			panic(err)
		}
	}()

	log.Println("INFO", "RemoteAddr:", request.RemoteAddr, request.RequestURI)

	// 验证登录
	authUser, authPassword, ok := request.BasicAuth()
	if !ok {
		writer.WriteHeader(401)
		return
	}

	if _, ok := cfg.Users[authUser]; !ok {
		writer.WriteHeader(401)
		return
	}
	if cfg.Users[authUser] != authPassword {
		writer.WriteHeader(401)
		return
	}

	query := request.URL.Query()

	scope := query.Get("scope")
	service := query.Get("service")
	account := query.Get("account")

	if len(account) > 0 && account != authUser {
		writer.WriteHeader(403)
		return
	}

	tmpToken := &tokenPayload{
		Aud: service,
	}

	scopes := strings.Split(scope, ":")

	if len(scope) > 0 {
		if len(scopes) != 3 {
			writer.WriteHeader(404)
			return
		}
		repo, exists := cfg.Repos[scopes[1]]
		if !exists {
			writer.WriteHeader(404)
			return
		}
		// 权限验证
		// 如果没有write权限 且 pull场景没有read权限
		if !(checkIn(authUser, repo.Write)) && !(scopes[2] == "pull" && checkIn(authUser, repo.Read)) {
			writer.WriteHeader(403)
			return
		}

		access := &access{
			Name: scopes[1],
		}
		access.Enable(scopes[2])

		tmpToken.AppendAccess(*access)

	} else if query.Get("offline_token") == "true" {
		// 登录场景
		// do nothing, direct return
	}

	tmpToken.Sub = account

	token, err := GenerateToken(&tokenHeader{
		Alg: "RS512",
		Typ: "JWT",
		X5c: []string{cfg.Certificate},
	}, tmpToken)

	if err != nil {
		log.Println("ERR", err)
		writer.WriteHeader(500)
	}

	writer.Header().Set("Content-Type", "application/json; charset:utf-8")

	res, err := json.Marshal(struct {
		Token string `json:"token"`
	}{
		Token: token,
	})

	if err != nil {
		log.Println("ERR", err)
		writer.WriteHeader(500)
		return
	}

	_, _ = writer.Write(res)

}

func parseConfig(configFilepath string) (*config, error) {

	cfg := &config{
		Port:  8000,
		Users: make(map[string]string),
		Repos: make(map[string]*repo),
	}

	file, err := ioutil.ReadFile(configFilepath)
	if err != nil {
		if _, ok := err.(*fs.PathError); ok {
			return nil, errors.New("configuration file not found")
		}
		return nil, err
	}

	err = json.Unmarshal(file, &cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil

}

func checkIn(target string, collection []string) bool {

	for _, v := range collection {
		if target == v {
			return true
		}
	}

	return false
}

func safeEncode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	encoded = strings.ReplaceAll(encoded, "=", "")
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")

	return encoded
}
