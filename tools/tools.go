package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

//The IP struct
type IP struct {
	Address    string
	ServerName string
	Delay      int
}

const (
	tmpOkIPFileName string = "ip_tmpok.txt"
	jsonIPFileName  string = "ip_output.txt"
)

func main() {
	tips()

}
func tips() {

	fmt.Print(`请选择需要处理的操作, 输入对应的数字并按下回车:

1. 提取 ip_tmpok.txt 中的IP, 用｜分隔以及 json 格式, 并生成ip_output.txt

2. IP格式互转 GoAgent <==> GoProxy, 并生成 ip_output.txt

请输入对应的数字：`)

	switch getInputFromCommand() {
	case "1":
		convertIP2JSON()
	case "2":
		goagent2goproxy()
	default:
		tips()

	}
}
func convertIP2JSON() {
	fmt.Print("\n请输入最大延迟（以毫秒计算），否则提取所有IP：")
	input := getInputFromCommand()
	var delay int
	var err error
	isAll := true
	if len(input) > 0 {
		delay, err = strconv.Atoi(input)
		if err != nil {
			fmt.Println("\n输入不正确，请重新输入。")
			convertIP2JSON()
			return
		}
		isAll = false
	}
	gws, gvs := writeJSONIP2File(delay, isAll)
	fmt.Printf("\ndelay: %dms, ip count: %d(gws: %d, gvs: %d)\n", delay, gws+gvs, gws, gvs)

	fmt.Println("\npress Enter to continue...")
	fmt.Scanln()
	tips()
}
func goagent2goproxy() {
	fmt.Println("请输入需要转换的IP, 可使用右键->粘贴：")
	rawips := getInputFromCommand()
	rawips = strings.TrimSpace(rawips)
	var ips string
	if strings.Contains(rawips, "|") {
		ips = strings.Trim(rawips, "|")
		ips = strings.Replace(ips, "|", "\",\"", -1)
		ips = "\"" + ips + "\""
	} else {
		ips = strings.Replace(rawips, "\",\"", "|", -1)
		ips = rawips[1 : len(rawips)-1]
	}
	fmt.Println()
	fmt.Println(ips)
	fmt.Println("\npress Enter to continue...")
	fmt.Scanln()
	tips()
}
func getInputFromCommand() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = input[:len(input)-2]

	return input
}

//get last ok ip
func getLastOkIP() []IP {
	m := make(map[string]IP)
	var checkedip IP
	var ips []IP
	if isFileExist(tmpOkIPFileName) {
		bytes, err := ioutil.ReadFile(tmpOkIPFileName)
		if err != nil {
			fmt.Printf("read file %s error: %v", tmpOkIPFileName, err)
		}
		lines := strings.Split(string(bytes), "\n")
		for _, line := range lines {
			ipInfo := strings.Split(line, " ")
			if len(ipInfo) == 6 {
				delay, _ := strconv.Atoi(ipInfo[1][:len(ipInfo[1])-2])
				checkedip = IP{
					Address:    ipInfo[0],
					Delay:      delay,
					ServerName: ipInfo[3],
				}
				m[ipInfo[0]] = checkedip
			}
		}
	}
	for _, v := range m {
		ips = append(ips, v)
	}
	return ips
}

/**
writeJSONIP2File: sorting ip, ridding duplicate ip, generating json ip and
bar-separated ip
*/
func writeJSONIP2File(delay int, isAll bool) (gws, gvs int) {
	okIPs := getLastOkIP()
	_, err := os.Create(jsonIPFileName)
	if err != nil {
		fmt.Printf("create file %s error: %v", jsonIPFileName, err)
	}
	var gaipbuf, gpipbuf bytes.Buffer
	for _, ip := range okIPs {

		if isAll {
			if ip.ServerName == "gws" {
				gws++
			}
			if ip.ServerName == "gvs" {
				gvs++
			}
			gaipbuf.WriteString(ip.Address)
			gaipbuf.WriteString("|")
			gpipbuf.WriteString("\"")
			gpipbuf.WriteString(ip.Address)
			gpipbuf.WriteString("\",")
		} else {
			if ip.Delay <= delay {
				if ip.ServerName == "gws" {
					gws++
				}
				if ip.ServerName == "gvs" {
					gvs++
				}
				gaipbuf.WriteString(ip.Address)
				gaipbuf.WriteString("|")
				gpipbuf.WriteString("\"")
				gpipbuf.WriteString(ip.Address)
				gpipbuf.WriteString("\",")
			}
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
	err = ioutil.WriteFile(jsonIPFileName, []byte(gaip+"\n\n\n"+gpip), 0755)
	if err != nil {
		fmt.Printf("write ip to file %s error: %v", jsonIPFileName, err)
	}
	return gws, gvs
}

//Whether file exists.
func isFileExist(file string) bool {
	_, err := os.Stat(file)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}
