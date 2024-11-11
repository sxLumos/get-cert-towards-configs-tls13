package main

import (
	"fmt"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/pop3"
	"log"
	"net"
	"time"
)

func POPScan(host string, port uint, ip net.IP, flags zgrab2.ScanFlags) (*tls.Certificates, string, string) {
	module := pop3.Module{}
	scanner := module.NewScanner().(*pop3.Scanner)

	// 2. 初始化 Scanner
	err := scanner.Init(flags)
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
		return nil, "", ""
	}

	// 3. 创建 ScanTarget 实例
	target := zgrab2.ScanTarget{
		IP:     ip,
		Port:   &port,
		Domain: host,
	}

	status, result, err := scanner.Scan(target)

	fmt.Printf("Scan status<%s:%d>: %v(%v)\n", host, port, status, err)
	if result != nil {
		scanResult := result.(*pop3.ScanResults)
		if scanResult != nil && scanResult.TLSLog != nil && scanResult.TLSLog.HandshakeLog != nil && scanResult.TLSLog.HandshakeLog.ServerCertificates != nil && scanResult.TLSLog.HandshakeLog.ServerHello != nil {
			version := scanResult.TLSLog.HandshakeLog.ServerHello.Version
			if scanResult.TLSLog.HandshakeLog.ServerHello.SupportedVersions != nil {
				version = scanResult.TLSLog.HandshakeLog.ServerHello.SupportedVersions.SelectedVersion
			}
			ciperSuit := scanResult.TLSLog.HandshakeLog.ServerHello.CipherSuite
			return scanResult.TLSLog.HandshakeLog.ServerCertificates, version.String(), ciperSuit.String()
		} else {
			return nil, "", ""
		}
	} else {
		return nil, "", ""
	}
}

func NewPOPFlags(port uint, hostname string, popSecure bool, STARTTLS bool, rootCAs string) zgrab2.ScanFlags {
	// 创建 zgrab2 扫描器配置
	flags := pop3.Flags{
		BaseFlags: zgrab2.BaseFlags{
			Port:           port,
			Name:           "pop_scan",
			Timeout:        10 * time.Second,
			Trigger:        "",
			BytesReadLimit: 0,
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
			Certificates:            "",
			CertificateMap:          "",
			RootCAs:                 rootCAs,
			NextProtos:              "",
			ServerName:              hostname,
			VerifyServerCertificate: true,
			NoECDHE:                 false,
			HeartbeatEnabled:        false,
			DSAEnabled:              false,
		},
		POP3Secure: popSecure, // 使用 --smtp 选项
		Verbose:    true,      // 可选：启用详细日志记录
		StartTLS:   STARTTLS,
	}
	return &flags
}

//func main() {
//	// 设置目标主机和端口
//	hostname := "pop3.163.com"
//	port := uint(995)
//
//	flags := NewPOPFlags(uint(port), hostname, true, false)
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
//	ips, _err := customResolver.LookupIP(ctx, "ip4", hostname)
//	if _err != nil {
//		fmt.Printf("failed to lookup IP: %v\n", _err)
//		return
//	}
//
//	for _, ip := range ips {
//		fmt.Println("IP:", ip)
//		err := POPScan(port, ip, flags, "")
//		if err != nil {
//
//		}
//	}
//}
