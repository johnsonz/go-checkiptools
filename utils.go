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
