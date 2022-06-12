package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/sync/errgroup"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
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

type token struct {
	tokenPayload *tokenPayload
}

func (token token) Generate() (string, error) {

	tmpPayload := *token.tokenPayload

	now := int(time.Now().Unix())
	exp := int(time.Now().Unix() + 600)

	tmpPayload.Iat = &now
	tmpPayload.Nbf = &now
	tmpPayload.Exp = &exp

	return "", nil
}

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

func (payload *tokenPayload) AppendAccess(access *access) {
	payload.Access = append(payload.Access, *access)
}

type access struct {
	noCopy noCopy
	sync.Mutex
	Type    string   `json:"type,omitempty"`
	Name    string   `json:"name,omitempty"`
	Actions []string `json:"actions,omitempty"`
}

func (access *access) Enable(act string) {
	access.Lock()
	defer access.Unlock()

	access.Actions = append(access.Actions, act)

}

type noCopy struct {
}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

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
	fmt.Println(cfg)

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

	tmpToken := &token{
		tokenPayload: &tokenPayload{
			Aud: service,
		},
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

		tmpToken.tokenPayload.AppendAccess(access)

	} else if query.Get("offline_token") == "true" {
		// 登录场景
		// do nothing, direct return
	}

	tokenJson, err := json.Marshal(tmpToken.tokenPayload)
	if err != nil {
		log.Println("ERR", err)
		writer.WriteHeader(500)
	}

	writer.Header().Set("Content-Type", "application/json; charset:utf-8")
	_, _ = writer.Write(tokenJson)

}

func parseConfig(configFilepath string) (*config, error) {

	cfg := &config{
		Port:  8000,
		Users: make(map[string]string),
		Repos: make(map[string]*repo),
	}

	file, err := ioutil.ReadFile(configFilepath)
	if err != nil {
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
