package utils

import "github.com/golang/glog"

//CheckErr Check error
func CheckErr(err error) {
	if err != nil {
		glog.Fatalln(err)
	}
}
