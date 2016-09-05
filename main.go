package main

import (
	"bytes"
	"checkip/utils"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
)

//Config Get config info from extra config.json file.
type Config struct {
	Concurrency     int      `json:"concurrency"`
	TimeOut         int      `json:"timeout"`
	OrgNames        []string `json:"organization"`
	GwsDomains      []string `json:"gws"`
	GvsDomains      []string `json:"gvs"`
	IsSort          bool     `json:"sort_tmpokfile"`
	IsCehckLastOKIP bool     `json:"check_last_okip"`
}

//The IP struct
type IP struct {
	address     string
	countryName string
	commonName  string
	orgName     string
	serverName  string
	timeDelay   int
	bandwidth   int
}

// The status of type IP
const (
	okIP = iota
	noIP
	errIP
)
const (
	configFileName   string = "config.json"
	certFileName     string = "cacert.pem"
	googleIPFileName string = "googleip.txt"
	tmpOkIPFileName  string = "ip_tmpok.txt"
	tmpErrIPFileName string = "ip_tmperr.txt"
	tmpNoIPFileName  string = "ip_tmpno.txt"
	okIPFileName     string = "ip.txt"
)

var config Config
var curDir string
var separator string
var err error
var certPool *x509.CertPool
var tlsConfig *tls.Config
var dialer net.Dialer

func init() {
	fmt.Println("loading...")
	if runtime.GOOS == "windows" {
		separator = "\r\n"
	} else {
		separator = "\n"
	}
	curDir, err = filepath.Abs(filepath.Dir(os.Args[0]))
	utils.CheckErr(err)
	parseConfig(curDir)
	loadCertPem()

	tlsConfig = &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: true,
	}
	dialer = net.Dialer{
		Timeout:   time.Millisecond * time.Duration(config.TimeOut),
		KeepAlive: 0,
		DualStack: false,
	}
}
func main() {

	flag.Set("logtostderr", "true")
	flag.Parse()
	createFile()

	jobs := make(chan string, config.Concurrency)
	done := make(chan bool, config.Concurrency)
	ips := getAllGoogleIP()

	fmt.Printf("Load google ip ok,line: %d, load default ip: %d%s",
		len(parseGoogleIP(readGoogleIP())), len(ips), separator)

	t0 := time.Now()
	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
	}()

	for i := 0; i < config.Concurrency; i++ {
		go doCheckIP(jobs, done)
	}
	for range done {
		<-done
	}
	t1 := time.Now()

	fmt.Printf("time: %fs%s", t1.Sub(t0).Seconds(), separator)
}

//cacert.pem
func loadCertPem() {
	certpem, err := ioutil.ReadFile(filepath.Join(curDir, certFileName))
	utils.CheckErr(err)

	certPool = x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certpem) {
		glog.Fatalf("Load %s error.\n", certFileName)
	}
}

//Parse config file
func parseConfig(dir string) {

	conf, err := ioutil.ReadFile(filepath.Join(dir, configFileName))
	utils.CheckErr(err)
	err = json.Unmarshal(conf, &config)
	utils.CheckErr(err)

}

//Read google ip from googleip.txt
func readGoogleIP() []byte {
	bytes, err := ioutil.ReadFile(filepath.Join(curDir, googleIPFileName))
	utils.CheckErr(err)
	return bytes
}

//Convert google ip from []byte to []string
func parseGoogleIP(bytes []byte) []string {
	return strings.Split(string(bytes), separator)
}

/**
  Parse google ip range, support the following formats:
  1. xxx.xxx.xxx.xxx
  2. xxx.xxx.xxx.xxx/xx
  3. xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx
*/
func parseGoogleIPRange(ipRange string) []string {
	var ips []string
	if strings.Contains(ipRange, "/") {
		//CIDR: https://zh.wikipedia.org/wiki/%E6%97%A0%E7%B1%BB%E5%88%AB%E5%9F%9F%E9%97%B4%E8%B7%AF%E7%94%B1
		ip, ipNet, err := net.ParseCIDR(ipRange)
		utils.CheckErr(err)
		for iptmp := ip.Mask(ipNet.Mask); ipNet.Contains(iptmp); inc(iptmp) {
			ips = append(ips, iptmp.String())
		}
		// remove network address and broadcast address
		return ips[1 : len(ips)-1]
	} else if strings.Contains(ipRange, "-") {
		startIP := net.ParseIP(ipRange[:strings.Index(ipRange, "-")])
		endIP := net.ParseIP(ipRange[strings.Index(ipRange, "-")+1:])

		for ip := startIP; bytes.Compare(ip, endIP) <= 0; inc(ip) {
			ips = append(ips, ip.String())
		}
	} else {
		ips = append(ips, ipRange)
	}
	return ips
}

//Get all parsed goole ip
func getAllGoogleIP() []string {
	ipRanges := parseGoogleIP(readGoogleIP())
	ipRanges = ipRanges[:len(ipRanges)-1]
	var ips []string
	for _, ipRange := range ipRanges {
		ips = append(ips, parseGoogleIPRange(ipRange)...)
	}
	return ips
}
func doCheckIP(jobs chan string, done chan bool) {
	for job := range jobs {
		checkIP(job)
		done <- true
	}
	close(done)
}
func checkIP(ip string) {
	var checkedip IP
	checkedip.address = ip

	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		glog.Infof("%s: %v%s", ip, err, separator)
		writeIPFile(checkedip, tmpErrIPFileName)
		return
	}
	defer conn.Close()

	t0 := time.Now()
	tlsClient := tls.Client(conn, tlsConfig)
	if err = tlsClient.Handshake(); err != nil {
		glog.Infof("%s: %v%s", ip, err, separator)
		writeIPFile(checkedip, tmpErrIPFileName)
		return
	}
	t1 := time.Now()

	if tlsClient.ConnectionState().PeerCertificates == nil {
		glog.Infof("%s: peer certificates error%s", ip, separator)
		writeIPFile(checkedip, tmpNoIPFileName)
		return
	}

	checkedip.timeDelay = int(t1.Sub(t0).Seconds() * 1000)

	peerCertSubject := tlsClient.ConnectionState().PeerCertificates[0].Subject
	checkedip.commonName = peerCertSubject.CommonName
	orgNames := peerCertSubject.Organization
	if len(orgNames) > 0 {
		checkedip.orgName = orgNames[0]
	}
	countryNames := peerCertSubject.Country
	if len(countryNames) > 0 {
		checkedip.countryName = countryNames[0]
	}

	for _, org := range config.OrgNames {
		if org == checkedip.orgName {
			var flag0, flag1 bool
			for _, gws := range config.GwsDomains {
				if gws == checkedip.commonName {
					checkedip.serverName = "gws"
					writeIPFile(checkedip, tmpOkIPFileName)
					flag0 = true
					break
				}
			}
			if !flag0 {
				for _, gvs := range config.GvsDomains {
					if gvs == checkedip.commonName {
						checkedip.serverName = "gvs"
						writeIPFile(checkedip, tmpOkIPFileName)
						flag1 = true
						break
					}
				}
			}
			if !flag0 && !flag1 {
				writeIPFile(checkedip, tmpNoIPFileName)
			}
		} else {
			writeIPFile(checkedip, tmpNoIPFileName)
		}
	}
	glog.Infof("%s: %s %s%s", checkedip.address, checkedip.commonName,
		checkedip.serverName, separator)
}

//Write IP to corresponding file
func writeIPFile(checkedip IP, file string) {
	f, err := os.OpenFile(filepath.Join(curDir, file), os.O_APPEND,
		os.ModeAppend)
	utils.CheckErr(err)
	_, err = f.WriteString(fmt.Sprintf("%-15s %-7s %-3s %-s %-s%s",
		checkedip.address, strconv.Itoa(checkedip.timeDelay)+"ms", checkedip.serverName,
		checkedip.commonName, checkedip.countryName, separator))
	utils.CheckErr(err)
	defer f.Close()
}

//Whether file exists.
func isFileExist(file string) bool {
	_, err := os.Stat(file)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

//Create files if they donnot exist.
func createFile() {
	if !isFileExist(filepath.Join(curDir, tmpOkIPFileName)) {
		_, err := os.Create(filepath.Join(curDir, tmpOkIPFileName))
		utils.CheckErr(err)
	}
	if !isFileExist(filepath.Join(curDir, tmpNoIPFileName)) {
		_, err := os.Create(filepath.Join(curDir, tmpNoIPFileName))
		utils.CheckErr(err)
	}
	if !isFileExist(filepath.Join(curDir, tmpErrIPFileName)) {
		_, err := os.Create(filepath.Join(curDir, tmpErrIPFileName))
		utils.CheckErr(err)
	}
}
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
