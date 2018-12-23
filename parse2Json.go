package main

import (
	"fmt"
	"encoding/json"
	"io/ioutil"
	"regexp"
	"path"
)

const (
	PARSER_NAME = "parse2Json"
	PARSER_VERSION = "0.1.0"
)

// function to parse the output of an nmap command to a json string
func parseNmap(fileContent []byte) []byte {
	type NmapOutput struct {
		Command struct {
			String string `json:"string"`
			Version string `json:"version"`
		} `json:"command"`
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
		Parser struct {
			Name string `json:"name"`
			Version string `json:"version"`
			RawInput string `json:"rawInput"`
		} `json:"parser"`
	}

	nmapOutput := NmapOutput{}

	regexHeader, err := regexp.Compile("# Nmap ([0-9.]+) scan initiated .+ as: ([^\n]+)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	header := regexHeader.FindStringSubmatch(string(fileContent))
	if len(header) > 1 {
		nmapOutput.Command.Version = header[1]
		nmapOutput.Command.String = header[2]
	}

	regexOs, err := regexp.Compile("Service Info: OS: ([^\n]+)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	os := regexOs.FindStringSubmatch(string(fileContent))
	if len(os) > 0 { nmapOutput.Os = os[1] }

	regexHostList, err := regexp.Compile("Nmap scan report for ([0-9.]{7,15})\nHost is up \\(([0-9\\.]+)s latency\\).\nMAC Address: ([0-9A-Fa-f:]{17}) \\(([^\\)]+)\\)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	hostList := regexHostList.FindAllStringSubmatch(string(fileContent), -1)
	if len(hostList) > 0 && len(hostList[0]) > 4 {
		for _, host := range hostList {
			hostJson := struct{
				IpAddress string `json:"ipAddress"`
				Latency string `json:"latency"`
				MacAddress string `json:"macAddress"`
				Maker string `json:"maker"`
			}{host[1], host[2], host[3], host[4]}
			nmapOutput.HostList = append(nmapOutput.HostList, hostJson) }
	}

	regexPortList, err := regexp.Compile("([0-9]+/[a-z]+)[ \t]+([a-z]+)[ \t]+([^ \n]+)[ \t]*([^\n]*)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	portList := regexPortList.FindAllStringSubmatch(string(fileContent), -1)
	if len(portList) > 0 && len(portList[0]) > 4 {
		for _, port := range portList {
			portJson := struct{
				Port string `json:"port"`
				State string `json:"state"`
				Service string `json:"service"`
				Version string `json:"version"`
			}{port[1], port[2], port[3], port[4]}
			nmapOutput.PortList = append(nmapOutput.PortList, portJson) }
	}

	nmapOutput.Parser.Name = PARSER_NAME
	nmapOutput.Parser.Version = PARSER_VERSION
	nmapOutput.Parser.RawInput = string(fileContent)

	jsonString, err := json.MarshalIndent(nmapOutput, "", "    ")
	if err != nil { fmt.Printf("Error: unable to marshal > %v\n", err); return nil }

	return jsonString
}

// function to parse the output of a dig command to a json string
func parseDig(fileContent []byte) []byte {
	type DigOutput struct {
		Command struct {
			String string `json:"string"`
			Version string `json:"version"`
		} `json:"command"`
		RecordList []struct {
			Host string `json:"host"`
			Ttl string `json:"ttl"`
			Type string `json:"type"`
			Record string `json:"record"`
		} `json:"recordList"`
		Parser struct {
			Name string `json:"name"`
			Version string `json:"version"`
			RawInput string `json:"rawInput"`
		} `json:"parser"`
	}

	digOutput := DigOutput{}

	regexHeader, err := regexp.Compile("; <<>> DiG ([0-9.]+) <<>> ([^\n]+)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	header := regexHeader.FindStringSubmatch(string(fileContent))
	if len(header) > 1 {
		digOutput.Command.Version = header[1]
		digOutput.Command.String = "dig " + header[2]
	}

	regexRecordList, err := regexp.Compile("\n([a-z.]+)[ \t]+([0-9]+)[ \t]+IN[ \t]+([A-Z]+)[ \t]+([^\n]+)")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	recordList := regexRecordList.FindAllStringSubmatch(string(fileContent), -1)
	if len(recordList) > 0 && len(recordList[0]) > 4 {
		for _, record := range recordList {
			recordJson := struct{
				Host string `json:"host"`
				Ttl string `json:"ttl"`
				Type string `json:"type"`
				Record string `json:"record"`
			}{record[1], record[2], record[3], record[4]}
			digOutput.RecordList = append(digOutput.RecordList, recordJson) }
	}

	digOutput.Parser.Name = PARSER_NAME
	digOutput.Parser.Version = PARSER_VERSION
	digOutput.Parser.RawInput = string(fileContent)

	jsonString, err := json.MarshalIndent(digOutput, "", "    ")
	if err != nil { fmt.Printf("Error: unable to marshal > %v\n", err); return nil }

	return jsonString
}


// function to parse the output of a traceroute command to a json string
func parseTraceroute(fileContent []byte) []byte {
	type TracerouteOutput struct {
		Command struct {
			String string `json:"string"`
			Target struct {
				HostName string `json:"hostName"`
				IpAddress string `json:"ipAddress"`
			} `json:"target"`
			MaxHops string `json:"maxHops"`
			PacketSize string `json:"packetSize"`
		} `json:"command"`
		HopList []struct {
			HopNumber string `json:"hopNumber"`
			HostName string `json:"hostName"`
			IpAddress string `json:"ipAddress"`
			Latency string `json:"latency"`
		} `json:"hopList"`
		Parser struct {
			Name string `json:"name"`
			Version string `json:"version"`
			RawInput string `json:"rawInput"`
		} `json:"parser"`
	}

	tracerouteOutput := TracerouteOutput{}

	regexHeader, err := regexp.Compile("traceroute to ([a-z0-9.-]+) \\(([0-9.]+)\\), ([0-9]+) hops max, ([0-9]+) byte packets")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	header := regexHeader.FindStringSubmatch(string(fileContent))
	if len(header) > 5 {
		tracerouteOutput.Command.String = header[1]
		tracerouteOutput.Command.Target.HostName = header[2]
		tracerouteOutput.Command.Target.IpAddress = header[3]
		tracerouteOutput.Command.MaxHops = header[4]
		tracerouteOutput.Command.PacketSize = header[5]
	}

	regexHopList, err := regexp.Compile("\n *([0-9]+) {2}([a-z0-9.-]+) \\(([0-9.]+)\\) {2}([0-9.]+) ms")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return nil }
	hopList := regexHopList.FindAllStringSubmatch(string(fileContent), -1)
	if len(hopList) > 0 && len(hopList[0]) > 4 {
		for _, hop := range hopList {
			hopJson := struct{
				HopNumber string `json:"hopNumber"`
				HostName string `json:"hostName"`
				IpAddress string `json:"ipAddress"`
				Latency string `json:"latency"`
			}{hop[1], hop[2], hop[3], hop[4]}
			tracerouteOutput.HopList = append(tracerouteOutput.HopList, hopJson)
		}
	}

	tracerouteOutput.Parser.Name = PARSER_NAME
	tracerouteOutput.Parser.Version = PARSER_VERSION
	tracerouteOutput.Parser.RawInput = string(fileContent)

	jsonString, err := json.MarshalIndent(tracerouteOutput, "", "    ")
	if err != nil { fmt.Printf("Error: unable to marshal > %v\n", err); return nil }

	return jsonString
}

// function to recursively scan a directory structure looking for files (files with extension .json and files/dirs prefixed with a dot "." are ignored)
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

	// regexes to select each different command output file
	regexNmap, err := regexp.Compile(".nmap")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return }
	regexDig, err := regexp.Compile(".dig")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return }
	regexTraceroute, err := regexp.Compile(".traceroute")
	if err != nil { fmt.Printf("Error: unable to compile regex > %v\n", err); return }

	fileList := dirScan(dirPath)
	for _, filePath := range fileList {
		fileContent, err := ioutil.ReadFile(filePath)
		if err != nil { fmt.Printf("Error: unable to read file > %v\n", err); return }

		// TODO: add check for already parsed .json file
		var jsonString []byte = nil
		if regexNmap.MatchString(filePath) == true {
			jsonString = parseNmap(fileContent)
		} else if regexDig.MatchString(filePath) == true {
			jsonString = parseDig(fileContent)
		} else if regexTraceroute.MatchString(filePath) == true {
			jsonString = parseTraceroute(fileContent)
		}

		if jsonString != nil {
			err = ioutil.WriteFile(filePath + ".json", jsonString, 0644)
			if err != nil { fmt.Printf("Error: unable to write file > %v\n", err); return }
		}
	}

	return
}
