package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func GetPEMTowardsURL(url string) (string, error) {
	// 创建 HTTP 客户端并跳过证书验证
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	// 发送 GET 请求
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to GET from %s: %v", url, err)
	}
	defer resp.Body.Close()

	// 检查响应状态(Go 的 http.Client 会自动处理重定向)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status: %s", resp.Status)
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// 将内容转换为字符串并返回
	pemContent := string(body)

	log.Printf("Certificate successfully downloaded from %s\n", url)
	return pemContent, nil
}

//func main() {
//	url := "https://d3frv9g52qce38.cloudfront.net/amazondefault/amazon_web_services_inc_2024.pem"
//	pemString, err := GetPEMTowardsURL(url)
//	if err != nil {
//		fmt.Printf("Error: %v\n", err)
//	} else {
//		fmt.Printf("%s\n", pemString)
//	}
//}
