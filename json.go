package main

import (
	"bytes"
	"encoding/json"
	"strings"
)

func parseJSONConfig(filename string) error {
	data := readFileWithoutErr(filename)
	data = readJSON(data)
	err := json.Unmarshal(data, &config)

	return err
}

func readJSON(data []byte) []byte {
	var lines []string
	for _, line := range strings.Split(strings.Replace(string(data), "\r\n", "\n", -1), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//") && line != "" {
			lines = append(lines, line)
		}
	}

	var b bytes.Buffer
	for i, line := range lines {
		if len(lines)-1 > i {
			nextLine := lines[i+1]
			if nextLine == "]" || nextLine == "]," || nextLine == "}" || nextLine == "}," {
				if strings.HasSuffix(line, ",") {
					line = strings.TrimSuffix(line, ",")
				}
			}
		}
		b.WriteString(line)
	}

	return b.Bytes()
}
