package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

//read file
func readFileWithoutErr(filename string) []byte {
	if !isFileExist(filename) {
		checkErr(fmt.Sprintf("file %s does not exist", filename), nil, Error)
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		//return nil, err
		checkErr(fmt.Sprintf("read file %s error: ", filename), err, Error)
	}

	return data
}

//read file
func readFile(filename string) ([]byte, error) {
	if !isFileExist(filename) {
		return nil, errors.New("file does not exist")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return data, nil
}

//Whether file exists.
func isFileExist(file string) bool {
	_, err := os.Stat(file)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	return true
}
