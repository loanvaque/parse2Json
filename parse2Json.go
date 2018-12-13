package main

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
	"regexp"
	"path"
)

const (
	CODE_VERSION = "2018121301"
)

// function to parse the output of an nmap scan to a json string
func parseNmap(fileContent []byte) []byte {
	type NmapScan struct {
		Command string `json:"command"`
		Version string `json:"version"`
		Os string `json:"os"`
		HostList []struct {
			IpAddress string `json:"ipAddress"`
			Latency string `json:"latency"`
			MacAddress string `json:"macAddress"`
			Maker string `json:"maker"`
		} `json:"hostList"`
		PortList []struct {
			Port string `json:"port"`
			State string `json:"state"`
			Service string `json:"service"`
			Version string `json:"version"`
		} `json:"portList"`
	}

	nmapScan := NmapScan{}

	regexCommand, err := regexp.Compile("# Nmap ([0-9.]+) scan initiated .+ as: ([^\n]+)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	command := regexCommand.FindStringSubmatch(string(fileContent))
	if len(command) > 1 {
		nmapScan.Version = command[1]
		nmapScan.Command = command[2]
	}

	regexOs, err := regexp.Compile("Service Info: OS: ([^\n]+)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	os := regexOs.FindStringSubmatch(string(fileContent))
	if len(os) > 0 { nmapScan.Os = os[1] }

	regexHostList, err := regexp.Compile("Nmap scan report for ([0-9.]+)\nHost is up \\(([0-9\\.]+)s latency\\).\nMAC Address: ([0-9A-Fa-f:]{17}) \\(([^\\)]+)\\)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	hostList := regexHostList.FindAllStringSubmatch(string(fileContent), -1)
	if len(hostList) > 0 && len(hostList[0]) > 4 {
		for _, host := range hostList { nmapScan.HostList = append(nmapScan.HostList, struct{IpAddress string `json:"ipAddress"`; Latency string `json:"latency"`; MacAddress string `json:"macAddress"`; Maker string `json:"maker"`}{host[1], host[2], host[3], host[4]}) }
	}

	regexPortList, err := regexp.Compile("([0-9]+/[a-z]+)[ \t]+([a-z]+)[ \t]+([^ \n]+)[ \t]*([^\n]*)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	portList := regexPortList.FindAllStringSubmatch(string(fileContent), -1)
	if len(portList) > 0 && len(portList[0]) > 4 {
		for _, port := range portList { nmapScan.PortList = append(nmapScan.PortList, struct{Port string `json:"port"`; State string `json:"state"`; Service string `json:"service"`; Version string `json:"version"`}{port[1], port[2], port[3], port[4]}) }
	}

	jsonString, err := json.MarshalIndent(nmapScan, "", "    ")
	if err != nil { fmt.Printf("Error: unable to marshal > %v\n", err); return nil }

	return jsonString
}

// function to parse the output of a dig query to a json string
func parseDig(fileContent []byte) []byte {
	type DigQuery struct {
		Command string `json:"command"`
		Version string `json:"version"`
		RecordList []struct {
			Host string `json:"host"`
			Ttl string `json:"ttl"`
			Type string `json:"type"`
			Record string `json:"record"`
		} `json:"recordList"`
	}

	digQuery := DigQuery{}

	regexHeader, err := regexp.Compile("; <<>> DiG ([0-9.]+) <<>> ([^\n]+)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	header := regexHeader.FindStringSubmatch(string(fileContent))
	if len(header) > 1 {
		digQuery.Version = header[1]
		digQuery.Command = "dig " + header[2]
	}

	regexRecordList, err := regexp.Compile("\n([a-z.]+)[ \t]+([0-9]+)[ \t]+IN[ \t]+([A-Z]+)[ \t]+([^\n]+)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	recordList := regexRecordList.FindAllStringSubmatch(string(fileContent), -1)
	if len(recordList) > 0 && len(recordList[0]) > 4 {
		for _, record := range recordList { digQuery.RecordList = append(digQuery.RecordList, struct{Host string `json:"host"`; Ttl string `json:"ttl"`; Type string `json:"type"`; Record string `json:"record"`}{record[1], record[2], record[3], record[4]}) }
	}

	jsonString, err := json.MarshalIndent(digQuery, "", "    ")
	if err != nil { fmt.Printf("Error: unable to marshal > %v\n", err); return nil }

	return jsonString
}

// function to recursively scan a directory structure looking for files to parse (.json extensions and names starting with a dot "." are ignored)
func dirScan(dirPath string) []string {
	var fileList []string
	files, err := ioutil.ReadDir(dirPath)
	if err != nil { fmt.Printf("Error: unable to read directory > %v\n", err); return nil }
	for _, file := range files {
		if file.Name()[0] == byte('.') { continue } // ignore hidden files and direcotories
		if file.IsDir() == true {
			fileListRecursed := dirScan(dirPath + "/" + file.Name())
			if fileListRecursed != nil { fileList = append(fileList, fileListRecursed...) }
		} else if path.Ext(file.Name()) != ".json" {
			fileList = append(fileList, dirPath + "/" + file.Name())
		}
	}
	return fileList
}

func main() {
	dirPath := "."

	regexNmap, err := regexp.Compile(".nmap.") // regex string to identify file names containing a nmap tag
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return }
	regexDig, err := regexp.Compile(".dig.") // regex string to identify file names containing a dig tag
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return }

	fileList := dirScan(dirPath)
	for _, filePath := range fileList {
		fileContent, err := ioutil.ReadFile(filePath)
		if err != nil { fmt.Printf("Error: unable to read file > %v\n", err); return }

		var jsonString []byte = nil
		if regexNmap.MatchString(filePath) == true {
			jsonString = parseNmap(fileContent)
		} else if regexDig.MatchString(filePath) == true {
			jsonString = parseDig(fileContent)
		}

		if jsonString != nil {
			err = ioutil.WriteFile(filePath + ".json", jsonString, 0644)
			if err != nil { fmt.Printf("Error: unable to write file > %v\n", err); return }
		}
	}

	return
}
