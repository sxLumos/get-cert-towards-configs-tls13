package main

import (
	"fmt"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/http"
	"log"
	"net"
	"time"
)

func HttpScan(hostname string, port uint, ip net.IP, flags http.Flags) (*tls.Certificates, string, string) {
	// 3. 创建 ScanTarget 实例
	target := zgrab2.ScanTarget{
		//Domain: hostname,
		IP:     ip,
		Port:   &port,
		Domain: hostname,
	}

	conn, err := target.Open(&flags.BaseFlags)
	if err != nil {
		log.Printf("Failed to open connection to <%v:%v> --- %v", hostname, port, err)
		return nil, "", ""
	}
	defer conn.Close()

	tlsConn, err := flags.TLSFlags.GetTLSConnection(conn)
	if err != nil {
		log.Printf("Failed to get TLS connection <%v:%v> --- %v", hostname, port, err)
		return nil, "", ""
	}
	defer tlsConn.Close()
	err = tlsConn.Handshake()
	fmt.Printf("Scan status<%s:%d>: %v\n", hostname, port, err)
	res_log := tlsConn.GetLog()
	if res_log != nil && res_log.HandshakeLog != nil && res_log.HandshakeLog.ServerCertificates != nil && res_log.HandshakeLog.ServerHello != nil {
		version := res_log.HandshakeLog.ServerHello.Version
		if res_log.HandshakeLog.ServerHello.SupportedVersions != nil {
			version = res_log.HandshakeLog.ServerHello.SupportedVersions.SelectedVersion
		}
		ciperSuit := res_log.HandshakeLog.ServerHello.CipherSuite
		return res_log.HandshakeLog.ServerCertificates, version.String(), ciperSuit.String()
	} else {
		return nil, "", ""
	}
}

func NewHTTPFlags(port uint, hostname string, rootCAs string) *http.Flags {
	// 创建 zgrab2 扫描器配置
	flags := http.Flags{
		BaseFlags: zgrab2.BaseFlags{
			Port:    port,
			Name:    "https_scan",
			Timeout: 10 * time.Second,
		},
		TLSFlags: zgrab2.TLSFlags{
			//Heartbleed:              false,
			SessionTicket:           true,
			ExtendedMasterSecret:    true,
			ExtendedRandom:          false,
			NoSNI:                   false,
			SCTExt:                  false,
			KeepClientLogs:          false,
			Time:                    "",
			CertificateMap:          "",
			RootCAs:                 rootCAs,
			NextProtos:              "",
			ServerName:              hostname,
			VerifyServerCertificate: true,
			NoECDHE:                 false,
			HeartbeatEnabled:        false,
			DSAEnabled:              false,
			MinVersion:              tls.VersionTLS10,
			MaxVersion:              tls.VersionTLS13,
		},
		Method:                   "GET",
		Endpoint:                 "/",
		FailHTTPToHTTPS:          false,
		UserAgent:                "Mozilla/5.0 zgrab/0.x",
		RetryHTTPS:               false,
		MaxSize:                  256,
		MaxRedirects:             0,
		FollowLocalhostRedirects: false,
		UseHTTPS:                 true,
		RedirectsSucceed:         false,
		OverrideSH:               false,
		WithBodyLength:           false,
		RawHeaders:               false,
	}
	return &flags
}

//func main() {
//	url := "mail.163.com"
//	port := uint(443)
//
//	flags := NewHTTPFlags(port, url, "IncludedRootsPEM.txt")
//
//	// 自定义解析器
//	customResolver := &net.Resolver{
//		PreferGo: true, // 使用Go的纯净DNS解析器
//		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
//			// 使用自定义的DNS服务器，替换为你想使用的DNS服务器地址
//			dnsServer := "8.8.8.8:53"
//			return net.Dial(network, dnsServer)
//		},
//	}
//
//	// 设置解析超时时间
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	// 使用自定义解析器解析主机名为IP地址
//	ips, _err := customResolver.LookupIP(ctx, "ip4", url)
//	if _err != nil {
//		fmt.Printf("failed to lookup IP: %v\n", _err)
//		return
//	}
//
//	for _, ip := range ips {
//		fmt.Println("IP:", ip)
//		cert, version, ciperSuits := HttpScan(url, port, ip, *flags)
//		if cert != nil {
//			fmt.Println(cert.Certificate.Parsed.Subject)
//		}
//		fmt.Println(version, ciperSuits)
//	}
//}
