package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//Config Get config info from extra config.json file.
type Config struct {
	Concurrency          int `json:"concurrency"`
	Timeout              int `json:"timeout"`
	HandshakeTimeout     int
	Delay                int      `json:"delay"`
	OrgNames             []string `json:"organization"`
	GwsDomains           []string `json:"gws"`
	GvsDomains           []string `json:"gvs"`
	SortOkIP             bool     `json:"sort_tmpokfile"`
	CheckLastOkIP        bool     `json:"check_last_okip"`
	CheckBandwidth       bool     `json:"check_bandwidth"`
	SortBandwidth        bool     `json:"sort_bandwidth"`
	BandwidthConcurrency int      `json:"bandwidth_concurrency"`
	BandwidthTimeout     int      `json:"bandwidth_timeout"`
	Write2Goproxy        bool     `json:"write_to_goproxy"`
	GoproxyPath          string   `json:"goproxy_path"`
}

const (
	configFileName   string = "main.json"
	certFileName     string = "cacert.pem"
	googleIPFileName string = "googleip.txt"
	tmpOkIPFileName  string = "ip_tmpok.txt"
	tmpErrIPFileName string = "ip_tmperr.txt"
	tmpNoIPFileName  string = "ip_tmpno.txt"
	jsonIPFileName   string = "ip.txt"
)

var config Config
var curDir string
var separator string
var certPool *x509.CertPool
var tlsConfig *tls.Config
var dialer net.Dialer

func init() {
	fmt.Println("initial...")
	parseConfig()
	config.HandshakeTimeout = config.Timeout
	loadCertPem()
	createFile()
	tlsConfig = &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: true,
	}
}

func main() {

	flag.Set("logtostderr", "true")
	flag.Parse()

	var lastOkIPs []string
	if config.CheckLastOkIP {
		tmpLastOkIPs := getLastOkIP()
		for _, ip := range tmpLastOkIPs {
			lastOkIPs = append(lastOkIPs, ip.Address)
		}
	}

	ips := append(lastOkIPs, getGoogleIP()...)

	fmt.Printf("load last checked ip ok, count: %d,\nload extra ip ok, line: %d, count: %d\n\n", len(lastOkIPs), len(getGoogleIPRange()), len(ips))
	time.Sleep(5 * time.Second)

	jobs := make(chan string, config.Concurrency)
	done := make(chan bool, config.Concurrency)

	//check all goole ip begin
	t0 := time.Now()
	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
	}()
	for ip := range jobs {
		done <- true
		go checkIP(ip, done)
	}
	for i := 0; i < cap(done); i++ {
		done <- true
	}
	//check all goole ip end

	if config.CheckBandwidth {

		jobs := make(chan IP, config.BandwidthConcurrency)
		done := make(chan bool, config.BandwidthConcurrency)

		ips := getLastOkIP()
		_, err := os.Create(tmpOkIPFileName)
		checkErr(fmt.Sprintf("create file %s error: ", tmpOkIPFileName), err, Error)
		// t2 := time.Now()
		go func() {
			for _, ip := range ips {
				jobs <- ip
			}
			close(jobs)
		}()
		for ip := range jobs {
			done <- true
			go checkBandwidth(ip, done)
		}
		for i := 0; i < cap(done); i++ {
			done <- true
		}
		// t3 := time.Now()
		// cost := int(t3.Sub(t2).Seconds())
	}
	gws, gvs, gpips := writeJSONIP2File()
	t1 := time.Now()
	cost := int(t1.Sub(t0).Seconds())
	fmt.Printf("\ntime: %ds, ok ip count: %d(gws: %d, gvs: %d)\n\n", cost, gws+gvs, gws, gvs)
	if config.Write2Goproxy {
		file := filepath.Join(config.GoproxyPath, "gae.user.json")
		if !isFileExist(file) {
			file = filepath.Join(config.GoproxyPath, "gae.json")
		}
		writeIP2Goproxy(file, gpips)
	}
	fmt.Println("\npress 'Enter' to continue...")
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			fmt.Printf("%c", '\007')
			time.Sleep(time.Second)
		}
		time.Sleep(time.Second * 3)
	}
	fmt.Scanln()
}

//Parse config file
func parseConfig() {
	conf, err := ioutil.ReadFile(configFileName)
	checkErr("read config file error: ", err, Error)
	err = json.Unmarshal(conf, &config)
	checkErr("parse config file error: ", err, Error)
}

//Load cacert.pem
func loadCertPem() {
	certpem, err := ioutil.ReadFile(certFileName)
	checkErr(fmt.Sprintf("read pem file %s error: ", certFileName), err, Error)
	certPool = x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certpem) {
		checkErr(fmt.Sprintf("load pem file %s error: ", certFileName), errors.New("load pem file error"), Error)
	}
}

func checkIP(ip string, done chan bool) {
	defer func() {
		<-done
	}()
	var checkedip IP
	checkedip.Address = ip
	checkedip.Bandwidth = -1
	checkedip.CountryName = "-"
	dialer = net.Dialer{
		Timeout:   time.Millisecond * time.Duration(config.Timeout),
		KeepAlive: 0,
		DualStack: false,
	}

	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		checkErr(fmt.Sprintf("%s dial error: ", ip), err, Debug)
		appendIP2File(checkedip, tmpErrIPFileName)
		return
	}
	defer conn.Close()

	t0 := time.Now()
	tlsClient := tls.Client(conn, tlsConfig)
	tlsClient.SetDeadline(time.Now().Add(time.Millisecond * time.Duration(config.HandshakeTimeout)))
	err = tlsClient.Handshake()

	if err != nil {
		checkErr(fmt.Sprintf("%s handshake error: ", ip), err, Debug)
		appendIP2File(checkedip, tmpErrIPFileName)
		return
	}
	defer tlsClient.Close()
	t1 := time.Now()

	if tlsClient.ConnectionState().PeerCertificates == nil {
		checkErr(fmt.Sprintf("%s peer certificates error: ", ip), errors.New("peer certificates is nil"), Debug)
		appendIP2File(checkedip, tmpNoIPFileName)
		return
	}

	checkedip.Delay = int(t1.Sub(t0).Seconds() * 1000)

	peerCertSubject := tlsClient.ConnectionState().PeerCertificates[0].Subject
	DNSNames := tlsClient.ConnectionState().PeerCertificates[0].DNSNames
	checkedip.CommonName = peerCertSubject.CommonName
	orgNames := peerCertSubject.Organization
	if len(peerCertSubject.Organization) > 0 {
		checkedip.OrgName = orgNames[0]
	}
	countryNames := peerCertSubject.Country
	if len(countryNames) > 0 {
		checkedip.CountryName = countryNames[0]
	}

	for _, org := range config.OrgNames {
		if org == checkedip.OrgName {
			for _, gws := range config.GwsDomains {
				for _, DNSName := range DNSNames {
					if strings.HasPrefix(DNSName, gws) {
						checkedip.ServerName = "gws"
						checkedip.CommonName = DNSName
						appendIP2File(checkedip, tmpOkIPFileName)
						goto OK
					}
				}
			}
			for _, gvs := range config.GvsDomains {
				for _, DNSName := range DNSNames {
					if strings.HasPrefix(DNSName, gvs) {
						checkedip.ServerName = "gvs"
						checkedip.CommonName = DNSName
						appendIP2File(checkedip, tmpOkIPFileName)
						goto OK
					}
				}
			}
			appendIP2File(checkedip, tmpNoIPFileName)
		} else {
			appendIP2File(checkedip, tmpNoIPFileName)
		}
	}
OK:
	checkErr(fmt.Sprintf("%s: %s %s %s %dms", checkedip.Address, checkedip.CommonName, checkedip.ServerName, checkedip.CountryName,
		checkedip.Delay), errors.New(""), Info)
}

//append ip to related file
func appendIP2File(checkedip IP, filename string) {
	f, err := os.OpenFile(filename, os.O_APPEND, os.ModeAppend)
	checkErr(fmt.Sprintf("open file %s error: ", filename), err, Error)
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s %dms %s %s %s %dKB/s\n", checkedip.Address, checkedip.Delay, checkedip.CommonName, checkedip.ServerName, checkedip.CountryName, checkedip.Bandwidth))
	checkErr(fmt.Sprintf("append ip to file %s error: ", filename), err, Error)
	f.Close()
}

//Create files if they donnot exist, or truncate them.
func createFile() {
	if !isFileExist(tmpOkIPFileName) {
		_, err := os.Create(tmpOkIPFileName)
		checkErr(fmt.Sprintf("create file %s error: ", tmpOkIPFileName), err, Error)
	}
	if !isFileExist(tmpNoIPFileName) {
		_, err := os.Create(tmpNoIPFileName)
		checkErr(fmt.Sprintf("create file %s error: ", tmpNoIPFileName), err, Error)
	}
	if !isFileExist(tmpErrIPFileName) {
		_, err := os.Create(tmpErrIPFileName)
		checkErr(fmt.Sprintf("create file %s error: ", tmpErrIPFileName), err, Error)
	}
}

/**
writeJSONIP2File: sorting ip, ridding duplicate ip, generating json ip and
bar-separated ip
*/
func writeJSONIP2File() (gws, gvs int, gpips string) {
	okIPs := getLastOkIP()
	if config.SortOkIP {
		sort.Sort(ByDelay{IPs(okIPs)})
	}
	err := os.Truncate(tmpOkIPFileName, 0)
	checkErr(fmt.Sprintf("truncate file %s error: ", tmpOkIPFileName), err, Error)
	var gaipbuf, gpipbuf bytes.Buffer
	for _, ip := range okIPs {
		if ip.ServerName == "gws" {
			gws++
		}
		if ip.ServerName == "gvs" {
			gvs++
		}
		appendIP2File(ip, tmpOkIPFileName)

		if ip.Delay <= config.Delay {
			gaipbuf.WriteString(ip.Address)
			gaipbuf.WriteString("|")
			gpipbuf.WriteString("\"")
			gpipbuf.WriteString(ip.Address)
			gpipbuf.WriteString("\",")
		}
	}
	gaips := gaipbuf.String()
	gpips = gpipbuf.String()

	if len(gaips) > 0 {
		gaips = gaips[:len(gaips)-1]
	}
	if len(gpips) > 0 {
		gpips = gpips[:len(gpips)-1]
	}
	err = ioutil.WriteFile(jsonIPFileName, []byte(gaips+"\n"+gpips), 0755)
	checkErr(fmt.Sprintf("write ip to file %s error: ", jsonIPFileName), err, Error)

	return gws, gvs, gpips
}

//writeIP2Goproxy: write json ip to gae.user.json or gae.json
func writeIP2Goproxy(file, jsonips string) {
	data, err := ioutil.ReadFile(file)
	checkErr(fmt.Sprintf("read file %s error: ", file), err, Error)
	content := string(data)
	if n := strings.Index(content, "HostMap"); n > -1 {
		tmp := content[n:]
		tmp = tmp[strings.Index(tmp, "[")+1 : strings.Index(tmp, "]")]
		content = strings.Replace(content, tmp, "\r\n\t\t\t"+jsonips+"\r\n\t\t\t", -1)
		err := ioutil.WriteFile(file, []byte(content), 0777)
		checkErr(fmt.Sprintf("write ip to file %s error: ", file), err, Error)
		fmt.Println("write ip to .json file successfully.")
	}
}
func checkBandwidth(ip IP, done chan bool) {
	defer func() {
		<-done
	}()
	ip.Bandwidth = -1
	if ip.ServerName == "gvs" {
		appendIP2File(ip, tmpOkIPFileName)
		checkErr(fmt.Sprintf("%s %s %s NaN", ip.Address, ip.CommonName, ip.ServerName), errors.New("gvs skipped"), Info)
		return
	}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip.Address, "443"))
	if err != nil {
		appendIP2File(ip, tmpOkIPFileName)
		checkErr(fmt.Sprintf("%s dial error: ", ip.Address), err, Info)
		return
	}
	defer conn.Close()

	tlsClient := tls.Client(conn, tlsConfig)
	tlsClient.SetDeadline(time.Now().Add(time.Minute * 5))
	_, err = tlsClient.Write([]byte("GET /storage/v1/b/google-code-archive/o/v2%2Fcode.google.com%2Fgogo-tester%2Fwiki%2F1m.wiki?alt=media HTTP/1.1\r\nHost: www.googleapis.com\r\nConnection: close\r\n\r\n"))
	if err != nil {
		appendIP2File(ip, tmpOkIPFileName)
		checkErr(fmt.Sprintf("%s tls write data error: ", ip.Address), err, Info)
		return
	}
	defer tlsClient.Close()

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	t0 := time.Now()
	for {
		n, err := tlsClient.Read(tmp)
		if err != nil {
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			break
		}
		buf = append(buf, tmp[:n]...)
	}
	t1 := time.Now()

	ip.Bandwidth = int(float64(len(buf)) / 1024 / t1.Sub(t0).Seconds())
	appendIP2File(ip, tmpOkIPFileName)
	checkErr(fmt.Sprintf("%s %s %s %dKB/s", ip.Address, ip.CommonName, ip.ServerName, ip.Bandwidth), errors.New(""), Info)
}
