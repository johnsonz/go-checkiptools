package main

import (
	"bytes"
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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/johnsonz/go-checkiptools/utils"

	"github.com/golang/glog"
)

//Config Get config info from extra config.json file.
type Config struct {
	Concurrency     int      `json:"concurrency"`
	TimeOut         int      `json:"timeout"`
	IPDelay         int      `json:"ipdelay"`
	OrgNames        []string `json:"organization"`
	GwsDomains      []string `json:"gws"`
	GvsDomains      []string `json:"gvs"`
	IsSortOkIP      bool     `json:"sort_tmpokfile"`
	IsCehckLastOkIP bool     `json:"check_last_okip"`
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

type IPs []IP

var config Config
var curDir string
var separator string
var err error
var certPool *x509.CertPool
var tlsConfig *tls.Config
var dialer net.Dialer

func init() {

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

	var ips []string
	var lastOkIPs []IP
	if config.IsCehckLastOkIP {
		lastOkIPs = getUniqueIP()
	}
	for _, lastOkIP := range lastOkIPs {
		ips = append(ips, lastOkIP.address)
	}
	ips = append(ips, getAllGoogleIP()...)
	fmt.Printf("load google ip ok,line: %d, load default ip: %d%s",
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
	for i := 0; i < config.Concurrency; i++ {
		<-done
	}
	total, gws, gvs := writeOkIP()
	t1 := time.Now()
	fmt.Printf("%stime: %fs, ok ip count: %d(gws: %d, gvs: %d) %s", separator,
		t1.Sub(t0).Seconds(), total, gws, gvs, separator)

	fmt.Println("press any key to continue...")
	fmt.Scanln()
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
	}
	done <- true
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
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("%s %dms %s %-s %-s%s",
		checkedip.address, checkedip.timeDelay, checkedip.serverName,
		checkedip.commonName, checkedip.countryName, separator))
	utils.CheckErr(err)
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

func getUniqueIP() []IP {
	m := make(map[string]IP)
	var ips []IP
	var ip IP
	bytes, err := ioutil.ReadFile(filepath.Join(curDir, tmpOkIPFileName))
	utils.CheckErr(err)
	lines := strings.Split(string(bytes), separator)
	lines = lines[:len(lines)-1]
	for _, line := range lines {
		ipInfo := strings.Split(line, " ")

		timed, _ := strconv.Atoi(ipInfo[1][:len(ipInfo[1])-2])
		if len(ipInfo) == 5 {
			ip = IP{
				address:     ipInfo[0],
				timeDelay:   timed,
				commonName:  ipInfo[2],
				serverName:  ipInfo[3],
				countryName: ipInfo[4],
			}
		} else {
			ip = IP{
				address:    ipInfo[0],
				timeDelay:  timed,
				commonName: ipInfo[2],
				serverName: ipInfo[3],
			}

		}
		m[ipInfo[0]] = ip
	}
	for _, value := range m {
		ips = append(ips, value)
	}
	return ips
}

/**
writeOkIP sorting ip, ridding duplicate ip, generating json ip and
bar-separated ip
*/
func writeOkIP() (total, gws, gvs int) {
	uniqueIPs := getUniqueIP()
	total = len(uniqueIPs)
	if config.IsSortOkIP {
		sort.Sort(IPs(uniqueIPs))
	}
	err := os.Truncate(filepath.Join(curDir, tmpOkIPFileName), 0)
	utils.CheckErr(err)
	var gaipbuf, gpipbuf bytes.Buffer
	for _, uniqueIP := range uniqueIPs {
		if uniqueIP.serverName == "gws" {
			gws++
		}
		if uniqueIP.serverName == "gvs" {
			gvs++
		}
		writeIPFile(uniqueIP, tmpOkIPFileName)
		if uniqueIP.timeDelay <= config.IPDelay {
			gaipbuf.WriteString(uniqueIP.address)
			gaipbuf.WriteString("|")
			gpipbuf.WriteString("\"")
			gpipbuf.WriteString(uniqueIP.address)
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
	err = ioutil.WriteFile(filepath.Join(curDir, okIPFileName),
		[]byte(gaip+"\n"+gpip), 0755)
	utils.CheckErr(err)

	return total, gws, gvs
}

func (ips IPs) Len() int           { return len(ips) }
func (ips IPs) Swap(i, j int)      { ips[i], ips[j] = ips[j], ips[i] }
func (ips IPs) Less(i, j int) bool { return ips[i].timeDelay < ips[j].timeDelay }
