package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func readFileWithoutErr(filename string) []byte {
	if isFileExist(filename) {
		checkErr(fmt.Sprintf("file %s does not exist", filename), nil, Error)
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		//return nil, err
		checkErr(fmt.Sprintf("read file %s error: ", filename), err, Error)
	}

	return data
}

//Whether file exists.
func isFileExist(file string) bool {
	_, err := os.Stat(file)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	return true
}
