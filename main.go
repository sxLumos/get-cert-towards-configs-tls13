package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/sourcegraph/conc/pool"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"github.com/zmap/zcrypto/tls"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConfigEntry represents a single configuration entry
type ConfigEntry struct {
	Config       string `json:"config"`
	ConfigSource string `json:"configSource"`
	ConfigType   string `json:"configType"`
	Extended     string `json:"extended"`
	SocketType   string `json:"socketType"`
}

type ProtoAndSocketType struct {
	Proto      string `json:"proto"`
	SocketType string `json:"socketType"`
}

type MyScanResult struct {
	Domain              string `json:"domain"`
	Config              string `json:"config"`       // pop.inner-active.mobi:995 or https://webmail.inner-active.mobi/
	ConfigType          string `json:"configType"`   // Hostname_Port or URL
	ConfigSource        string `json:"configSource"` // Autodiscover、FromDNS...
	TLSVersion          string `json:"tlsVersion"`
	CipherSuite         string `json:"cipherSuite"`
	IsTrusted           bool   `json:"isTrusted"` // is certificate trusted?
	VerificationProcess string `json:"verificationProcess"`
	IsMatchDomain       bool   `json:"isMatchDomain"`
	IsSameDomain        bool   `json:"isSameDomain"`
	ExtractedDomain     string `json:"extractedDomain"`
	/*
		Extended:
			若configSource为FromDNS，此处为获取DNSRecord的protocolPrefix + domain（_imap._tcp.google.com）
			若configSource为包含XML类型的数据，则为解析所得的protocol type
			若config为Guess，则为根据端口号所得的协议，例如993 or 143 -> imap
	*/
	Extended     string `json:"extended"`
	ServerType   string `json:"serverType"`   // IMAP Server、Http Server
	IP           net.IP `json:"ip"`           // ipv4
	Certificates string `json:"certificates"` // pem格式的证书 certificate(leaf cert) and chain(intermediate cert;root cert)
	Banner       string `json:"banner"`       // smtp: banner
}

type JobInfo struct {
	Entry  ConfigEntry `json:"entry"`
	Domain string      `json:"domain"`
}

var portToSocketType = map[int]string{ // 用于DNS SRV的形式
	465: "SSL",
	587: "STARTTLS",
	25:  "STARTTLS",
	143: "STARTTLS",
	993: "SSL",
	110: "STARTTLS",
	995: "SSL",
}

// ConfigData represents the overall structure of the JSON data
type ConfigData map[string][]ConfigEntry

var (
	hostToIP  = map[string]net.IP{}
	hostMutex = sync.RWMutex{} // 读写锁
)

func domainToIPAddress(hostname string) (net.IP, error) {
	// 使用读锁读取
	hostMutex.RLock()
	if ip, ok := hostToIP[hostname]; ok {
		hostMutex.RUnlock()
		return ip, nil
	}
	hostMutex.RUnlock()
	// 自定义解析器
	customResolver := &net.Resolver{
		PreferGo: true, // 使用Go的纯净DNS解析器
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// 使用自定义的DNS服务器
			dnsServer := "8.8.8.8:53"
			return net.Dial(network, dnsServer)
		},
	}

	// 设置解析超时时间
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 使用自定义解析器解析主机名为IP地址
	ips, _err := customResolver.LookupIP(ctx, "ip4", hostname)
	if _err != nil {
		return nil, _err
	}
	if len(ips) == 0 {
		return nil, errors.New("no IP addresses found")
	}
	// 写锁保护写入
	hostMutex.Lock()
	hostToIP[hostname] = ips[0]
	hostMutex.Unlock()
	return ips[0], nil
}

func parseHostPort(hostPort string) (string, int, error) {
	parts := strings.Split(hostPort, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid input: %s", hostPort)
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %v", err)
	}

	return parts[0], port, nil
}

// ConvertCertificatesToPEM 将 Certificates 对象转换为 PEM 格式的字符串
func ConvertCertificatesToPEM(certificates *tls.Certificates) (string, bool, bool, string) {
	var pemString string
	var validResult = false
	var isMatchDomain = false
	var validError = ""
	if certificates.Validation != nil {
		validResult = certificates.Validation.BrowserTrusted
		validError = certificates.Validation.BrowserError
		isMatchDomain = certificates.Validation.MatchesDomain
	}
	// 处理主证书
	if len(certificates.Certificate.Raw) > 0 {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificates.Certificate.Raw,
		})
		pemString += string(certPEM)
	}

	// 处理证书链
	for _, chainCert := range certificates.Chain {
		if len(chainCert.Raw) > 0 {
			chainPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: chainCert.Raw,
			})
			pemString += string(chainPEM)
		}
	}

	return pemString, validResult, isMatchDomain, validError
}

func addResult(result MyScanResult) {
	// 将结果添加到全局 results 切片
	mu.Lock()
	results = append(results, result)
	mu.Unlock()
}

func extractETLDDomain(hostname string, domain string, list *publicsuffix.List) (string, bool) {
	eTLDPlusOne, err := publicsuffix.DomainFromListWithOptions(list, hostname, nil)
	if err != nil {
		// 如果无法利用PSL提取主机名中eTLD + 1则直接返回hostname，并判断<.domain>是不是hostname后缀
		return hostname, hostname == domain || strings.HasSuffix(hostname, "."+domain)
	}
	// tranco: memset.net    google + PSL
	// http://autoconfig.memset.net/...
	// 1. VMC 、2.保留chain？
	return eTLDPlusOne, eTLDPlusOne == domain || strings.HasSuffix(eTLDPlusOne, "."+domain)
}

func scan(job JobInfo, rootCAs string, list *publicsuffix.List) {
	entry := job.Entry
	domain := job.Domain
	if entry.ConfigType == "URL" {
		/*
			对于 https://d3frv9g52qce38.cloudfront.net/amazondefault/amazon_web_services_inc_2024.pem
			先下载.pem证书，然后访问其https(443)

			对于其他 https://webmail.telegram.org/
			访问其https(443)，具体过程如下：
				- 提取https URL中的host
				- host -> []ips
				- for _, ip := range ips { Scan(ip:443) }
		*/

		if strings.HasSuffix(entry.Config, ".pem") {
			certString, _errHttp := GetPEMTowardsURL(entry.Config)
			if _errHttp == nil {
				parsedURL, errUrl := url.Parse(entry.Config)
				if errUrl != nil {
					return
				}
				extractedETLDDomain, isSameDomain := extractETLDDomain(parsedURL.Hostname(), domain, list)
				result := MyScanResult{
					Domain:              domain,
					Config:              entry.Config,
					ConfigType:          entry.ConfigType,
					ConfigSource:        entry.ConfigSource,
					IsTrusted:           false, // 忽略对VMC的验证，后续单独讨论？
					VerificationProcess: "",
					IsMatchDomain:       false,
					IsSameDomain:        isSameDomain,
					ExtractedDomain:     extractedETLDDomain,
					Extended:            entry.Extended,
					ServerType:          "HTTP",
					IP:                  net.IPv4zero,
					Certificates:        certString,
					Banner:              "",
				}
				addResult(result)
			}
		}
		parsedURL, errUrl := url.Parse(entry.Config)
		if errUrl != nil {
			return
		}
		ip, errToip := domainToIPAddress(parsedURL.Hostname())
		if errToip != nil {
			return
		}
		flags := NewHTTPFlags(uint(443), parsedURL.Hostname(), rootCAs)
		serverCertificates, version, ciperSuit := HttpScan(parsedURL.Hostname(), uint(443), ip, *flags)
		if serverCertificates == nil {
			return
		}
		serverCertificatesString, isTrusted, isMatchDomain, validError := ConvertCertificatesToPEM(serverCertificates)
		extractedETLDDomain, isSameDomain := extractETLDDomain(parsedURL.Hostname(), domain, list)
		result := MyScanResult{
			Domain:              domain,
			Config:              entry.Config,
			ConfigType:          entry.ConfigType,
			ConfigSource:        entry.ConfigSource,
			TLSVersion:          version,
			CipherSuite:         ciperSuit,
			IsTrusted:           isTrusted,
			VerificationProcess: validError,
			IsMatchDomain:       isMatchDomain,
			IsSameDomain:        isSameDomain,
			ExtractedDomain:     extractedETLDDomain,
			Extended:            entry.Extended,
			ServerType:          "HTTP",
			IP:                  ip,
			Certificates:        serverCertificatesString,
			Banner:              "",
		}
		addResult(result)
	} else if entry.ConfigType == "Hostname_Port" {
		/*
			var portToProto = map[int]ProtoAndSocketType{
				465: {"smtp", "STARTTLS"},
				587: {"smtp", "SSL"},
				143: {"smtp", "STARTTLS"},
				993: {"imap", "SSL"},
				110: {"pop", "STARTTLS"},
				995: {"pop", "SSL"},
			}

			对于hostname:port，过程如下：
				- hostname -> []ips
				- for _, ip := range ips{
					flag.SMTPSecure = SocketType == "SSL"
					flag.STARTTLS = SocketType == "STARTTLS"
					Scan(ip:port, flag)
				}
		*/
		hostname, port, errHostname := parseHostPort(entry.Config) // hostname:port -> hostname port
		if errHostname != nil {
			return
		}
		ip, errToip := domainToIPAddress(hostname)
		fmt.Println(ip)
		if errToip != nil {
			return
		}
		extractedETLDDomain, isSameDomain := extractETLDDomain(hostname, domain, list)
		var protoAndSocket ProtoAndSocketType
		if entry.ConfigSource == "FromDNS_SRV"{
			var socketType string
			var exists bool
			socketType, exists = portToSocketType[port]
			if !exists {
				socketType = "SSL"
			}
			if strings.HasSuffix(entry.Extended, "_submission") {
				protoAndSocket = ProtoAndSocketType{
					SocketType: socketType,
					Proto:      "SMTP",
				}
			} else if strings.HasSuffix(entry.Extended, "_imap") {
				protoAndSocket = ProtoAndSocketType{
					SocketType: socketType,
					Proto:      "IMAP",
				}
			} else if strings.HasSuffix(entry.Extended, "_pop") {
				protoAndSocket = ProtoAndSocketType{
					SocketType: socketType,
					Proto:      "POP",
				}
			} else {
				return
			}
		} else if entry.ConfigSource == "FromDNS_MX" {
			protoAndSocket = ProtoAndSocketType{
				SocketType: "STARTTLS",
				Proto:      "SMTP",
			}
		} else { // Guess方法
			protoAndSocket.Proto = entry.Extended
			protoAndSocket.SocketType = entry.SocketType
			if protoAndSocket.SocketType != "SSL_TLS" && protoAndSocket.SocketType != "STARTTLS" {
				return
			}
		}
		switch protoAndSocket.Proto {
		case "SMTP":
			flags := NewSMTPFlags(uint(port), hostname, protoAndSocket.SocketType == "SSL_TLS", protoAndSocket.SocketType == "STARTTLS", rootCAs)
			banner, serverCertificates, version, ciperSuit := SMTPScan(hostname, uint(port), ip, flags)
			if serverCertificates == nil {
				return
			}
			serverCertificatesString, isTrusted, isMatchDomain, validError := ConvertCertificatesToPEM(serverCertificates)
			result := MyScanResult{
				Domain:              domain,
				Config:              entry.Config,
				ConfigType:          entry.ConfigType,
				ConfigSource:        entry.ConfigSource,
				TLSVersion:          version,
				CipherSuite:         ciperSuit,
				IsTrusted:           isTrusted,
				VerificationProcess: validError,
				IsMatchDomain:       isMatchDomain,
				IsSameDomain:        isSameDomain,
				ExtractedDomain:     extractedETLDDomain,
				Extended:            entry.Extended,
				ServerType:          "SMTP",
				IP:                  ip,
				Certificates:        serverCertificatesString,
				Banner:              banner,
			}
			addResult(result)
		case "IMAP":
			flags := NewIMAPFlags(uint(port), hostname, protoAndSocket.SocketType == "SSL_TLS", protoAndSocket.SocketType == "STARTTLS", rootCAs)
			banner, serverCertificates, version, ciperSuit := IMAPScan(hostname, uint(port), ip, flags)
			if serverCertificates == nil {
				return
			}
			serverCertificatesString, isTrusted, isMatchDomain, validError := ConvertCertificatesToPEM(serverCertificates)
			result := MyScanResult{
				Domain:              domain,
				Config:              entry.Config,
				ConfigType:          entry.ConfigType,
				ConfigSource:        entry.ConfigSource,
				TLSVersion:          version,
				CipherSuite:         ciperSuit,
				IsTrusted:           isTrusted,
				VerificationProcess: validError,
				IsMatchDomain:       isMatchDomain,
				IsSameDomain:        isSameDomain,
				ExtractedDomain:     extractedETLDDomain,
				Extended:            entry.Extended,
				ServerType:          "IMAP",
				IP:                  ip,
				Certificates:        serverCertificatesString,
				Banner:              banner,
			}
			addResult(result)
		case "POP":
			flags := NewPOPFlags(uint(port), hostname, protoAndSocket.SocketType == "SSL_TLS", protoAndSocket.SocketType == "STARTTLS", rootCAs)
			banner, serverCertificates, version, ciperSuit := POPScan(hostname, uint(port), ip, flags)
			if serverCertificates == nil {
				return
			}
			serverCertificatesString, isTrusted, isMatchDomain, validError := ConvertCertificatesToPEM(serverCertificates)
			result := MyScanResult{
				Domain:              domain,
				Config:              entry.Config,
				ConfigType:          entry.ConfigType,
				ConfigSource:        entry.ConfigSource,
				TLSVersion:          version,
				CipherSuite:         ciperSuit,
				IsTrusted:           isTrusted,
				VerificationProcess: validError,
				IsMatchDomain:       isMatchDomain,
				IsSameDomain:        isSameDomain,
				ExtractedDomain:     extractedETLDDomain,
				Extended:            entry.Extended,
				ServerType:          "POP",
				IP:                  ip,
				Certificates:        serverCertificatesString,
				Banner:              banner,
			}
			addResult(result)
		default:
			fmt.Printf("Unsupported protocol: %s\n", protoAndSocket.Proto)
		}
	}
}

var (
	results []MyScanResult
	mu      sync.Mutex // 用于保护共享资源 results
)

func main() {
	startT := time.Now() //计算当前时间

	// Define the number of workers in the scanning pool
	numWorkers := 80

	// 加载PSL
	list, err := publicsuffix.NewListFromFile("public_suffix_list.dat", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Open the JSON file
	file, err := os.Open("test.json") // ConfigProcessResult.json、 test.json
	rootCAsPath := "IncludedRootsPEM.txt"
	if err != nil {
		log.Fatalf("failed to open file: %v", err)
	}
	defer file.Close()

	// Read the file's content
	byteValue, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("failed to read file: %v", err)
	}

	// Parse the JSON data
	var configData ConfigData
	err = json.Unmarshal(byteValue, &configData)
	if err != nil {
		log.Fatalf("failed to unmarshal JSON: %v", err)
	}

	p := pool.New().WithMaxGoroutines(numWorkers)

	all := len(configData)
	fmt.Printf("配置文件中包含%d个域名的配置信息\n", all)
	cnt := 0
	var wg sync.WaitGroup
	// Print the parsed data
	for domain, entries := range configData {
		cnt++
		fmt.Printf("Domain: %s\n", domain)
		for _, entry := range entries {
			e := entry
			d := domain
			fmt.Printf("---------- No.%d <ALL: %d> ----------\n", cnt, all)
			fmt.Printf("-Config: %s\n", e.Config)
			fmt.Printf("-ConfigSource: %s\n", e.ConfigSource)
			fmt.Printf("-ConfigType: %s\n", e.ConfigType)
			fmt.Printf("-Extended: %s\n", e.Extended)
			fmt.Printf("-SocketType: %s\n\n", e.SocketType)
			fmt.Printf("--------------------------\n")
			wg.Add(1)
			p.Go(func() {
				defer wg.Done()
				scan(JobInfo{Entry: e, Domain: d}, rootCAsPath, list)
			})
		}
		//break
	}
	wg.Wait()

	// Open output file for results
	outputFile, err := os.Create("scan_results_50w_100w_part2.txt")
	if err != nil {
		log.Fatalf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	for _, result := range results {
		jsonData, err := json.Marshal(result)
		if err != nil {
			fmt.Println("JSON marshaling failed:", err)
			return
		}

		_, err = outputFile.Write(jsonData)
		if err != nil {
			fmt.Println("Failed to write to file:", err)
			return
		}

		_, err = outputFile.WriteString("\n") // 写入换行符
		if err != nil {
			fmt.Println("Failed to write newline to file:", err)
			return
		}
	}

	fmt.Println("Scan completed and results saved to scan_results.json")

	tc := time.Since(startT) //计算耗时
	fmt.Printf("time cost = %v\n", tc)
}
