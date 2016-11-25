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
	"sort"
	"time"
)

//Config Get config info from extra config.json file.
type Config struct {
	Concurrency          int      `json:"concurrency"`
	Timeout              int      `json:"timeout"`
	HandshakeTimeout     int      `json:"handshake_timeout"`
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
}

const (
	configFileName   string = "config.json"
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
	parseConfig()
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
	time.Sleep(10 * 1000)

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
	total, gws, gvs := writeJSONIP2File()
	t1 := time.Now()
	cost := int(t1.Sub(t0).Seconds())
	fmt.Printf("\ntime: %ds, ok ip count: %d(gws: %d, gvs: %d)\n\n", cost, total, gws, gvs)

	fmt.Println("\npress 'Enter' to continue...")
	fmt.Scanln()
}

//Parse config file
func parseConfig() {
	conf, err := ioutil.ReadFile(configFileName)
	checkErr("read config file error: ", err, Info)
	err = json.Unmarshal(conf, &config)
	checkErr("parse config file error: ", err, Info)
}

//Load cacert.pem
func loadCertPem() {
	certpem, err := ioutil.ReadFile(certFileName)
	checkErr(fmt.Sprintf("read pem file %s error: ", certFileName), err, Info)
	certPool = x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certpem) {
		checkErr(fmt.Sprintf("load pem file %s error: ", certFileName), errors.New("load pem file error"), Info)
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
			var flag0, flag1 bool
			for _, gws := range config.GwsDomains {
				if gws == checkedip.CommonName {
					checkedip.ServerName = "gws"
					appendIP2File(checkedip, tmpOkIPFileName)
					flag0 = true
					break
				}
			}
			if !flag0 {
				for _, gvs := range config.GvsDomains {
					if gvs == checkedip.CommonName {
						checkedip.ServerName = "gvs"
						appendIP2File(checkedip, tmpOkIPFileName)
						flag1 = true
						break
					}
				}
			}
			if !flag0 && !flag1 {
				appendIP2File(checkedip, tmpNoIPFileName)
			}
		} else {
			appendIP2File(checkedip, tmpNoIPFileName)
		}
	}
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
func writeJSONIP2File() (total, gws, gvs int) {
	okIPs := getLastOkIP()
	total = len(getLastOkIP())
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
	gaip := gaipbuf.String()
	gpip := gpipbuf.String()

	if len(gaip) > 0 {
		gaip = gaip[:len(gaip)-1]
	}
	if len(gpip) > 0 {
		gpip = gpip[:len(gpip)-1]
	}
	err = ioutil.WriteFile(jsonIPFileName, []byte(gaip+"\n"+gpip), 0755)
	checkErr(fmt.Sprintf("write ip to file %s error: ", jsonIPFileName), err, Error)

	return total, gws, gvs
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
