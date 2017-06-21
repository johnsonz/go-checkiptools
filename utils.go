package main

import (
	"os"

	"github.com/golang/glog"
)

//custom log level
const (
	Info = iota
	Warning
	Debug
	Error
)

//CheckErr checks given error
func checkErr(messge string, err error, level int) {
	if err != nil {
		switch level {
		case Info, Warning, Debug:
			glog.Infoln(messge, err)
		case Error:
			glog.Fatalln(messge, err)
		}
	}
}

//Whether file exists.
func isFileExist(file string) bool {
	_, err := os.Stat(file)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

//convert type map[string]string to array
func convertMap2Array(m map[string]string) (s []string) {
	for _, v := range m {
		s = append(s, v)
	}

	return s
}

//convert type array to map[string]string
func convertArray2Map(s []string) (m map[string]string) {
	for _, v := range s {
		m[v] = v
	}
	return m
}
