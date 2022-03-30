package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

type client struct {
	client                   http.Client
	host                     string
	wasabi_access_key_id     string
	wasabi_secret_access_key string
	wasabi_region            string
}

func get_date() string {
	return fmt.Sprint(time.Now().UTC().Format("20060102T150405Z"))
}

type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Xmlns   string   `xml:"xmlns,attr"`
	Owner   Owner    `xml:"Owner"`
	Buckets Buckets  `xml:"Buckets"`
}

type Owner struct {
	XMLName     xml.Name `xml:"Owner"`
	Id          string   `xml:"ID"`
	DisplayName string   `xml:"DisplayName"`
}

type Buckets struct {
	XMLName xml.Name `xml:"Buckets"`
	Bucket  []Bucket `xml:"Bucket"`
}

type Bucket struct {
	XMLName      xml.Name `xml:"Bucket"`
	Name         string   `xml:"Name"`
	CreationDate string   `xml:"CreationDate"`
}

func hmac_sha256(secret string, data string) string {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(data))

	// Get result and encode as hexadecimal string
	return hex.EncodeToString(h.Sum(nil))
}

func hex_sha256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

type Header struct {
	key, value string
}

func (c client) ListBuckets() (*string, error) {
	endpoint := "http://s3.wasabisys.com"
	http_method := "GET"

	wasabi_access_key_id := os.Getenv("WASABI_ACCESS_KEY_ID")
	wasabi_secret_access_key := os.Getenv("WASABI_SECRET_ACCESS_KEY")

	wasabi_region := "us-east-1"
	wasabi_service := "s3"
	date := "20220330T013950Z"
	// date := get_date()
	signature := "8cd8edf7e23e38dafa29f9b394c1f889f72c0140adb48f3d8559e27fd9c5e321"

	// construct content sha256

	content_sha256 := hex_sha256("")
	//end contruct content sha256

	// construct headers
	headers := [3]Header{
		{"Host", endpoint},
		{"X-Amz-Content-Sha256", content_sha256},
		{"X-Amz-Date", date},
	}

	// construct canonical request
	canonical_uri := fmt.Sprintf("%s", "/")
	canonical_query_string := ""
	canonical_headers := ""
	signed_headers := ""
	for index, header := range headers {
		signed_headers += header.key
		if index+1 < len(headers) {
			signed_headers += ";"
		}
		canonical_headers += fmt.Sprintf("%s:%s\n", strings.ToLower(header.key), strings.TrimSpace(header.value))
	}
	hashed_payload := hex_sha256("")

	canonical_request := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", http_method, canonical_uri, canonical_query_string, canonical_headers, signed_headers, hashed_payload)

	//end  construct canonical request

	// construct string to sign
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", date[:8], wasabi_region, wasabi_service)

	string_to_sign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", date, scope, hex_sha256(canonical_request))
	fmt.Printf("%s\n\n", string_to_sign)

	//end construct string to sign

	//construct signature

	date_key := hmac_sha256(fmt.Sprintf("AWS4%s", wasabi_secret_access_key), date[:8])
	date_region_key := hmac_sha256(date_key, wasabi_region)
	date_region_service_key := hmac_sha256(date_region_key, wasabi_service)
	signing_key := hmac_sha256(date_region_service_key, "aws4_request")

	calc_signature := hmac_sha256(signing_key, string_to_sign)
	fmt.Printf("postman:    %s\ncalculated: %s\n\n", signature, calc_signature)
	//end construct signature

	req, err := http.NewRequest(http_method, endpoint, nil)

	// add authorization
	req.Header.Add("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", wasabi_access_key_id, scope, signed_headers, signature))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	// req.Header.Add("host", endpoint)
	for _, header := range headers {
		req.Header.Add(header.key, header.value)
	}
	res, err := c.client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	strbody := string(body)
	var result ListAllMyBucketsResult
	xml.Unmarshal(body, &result)
	json_result, _ := json.Marshal(result)
	fmt.Printf("%s\n\n", string(json_result))
	return &strbody, nil
}

func main() {
	client := client{client: http.Client{}}
	body, _ := client.ListBuckets()

	fmt.Println(*body)
}
