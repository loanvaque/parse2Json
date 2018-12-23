# Parse 2 Json

Parsing of shell commands output to json strings

## Process

1. Scan directory recursively
2. Find file names matching a pattern from a list of recognised patterns
3. Parse the content of the file according to the matched pattern in the file name
4. Convert the obtained elements to a json string
5. Write the json string to a file with the extenion ".json"

## File names

The names of the files to be parsed must contain one of the expected patterns\
Example: "github_ns_records.dig.txt" (".dig")

The names of the output files will be the same as the names of the original files, appended with the extension ".json"\
Example: "github_ns_records.dig.txt.json" (".json")

## Regex patterns

File contents currently parseable:

- **nmap** (https://linux.die.net/man/1/nmap)
- **dig** (https://linux.die.net/man/1/dig)
- **traceroute** (https://linux.die.net/man/8/traceroute)

More regex patterns will be added according to personal needs or requests

## Parsing of file content

The recognised pattern in the file name indicates the regex to be aplied

Example:\
Output of a dig command:

```
; <<>> DiG 9.10.6 <<>> github.com +nostats
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60876
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;github.com.            IN  A

;; ANSWER SECTION:
github.com.     59  IN  A   140.82.118.4
github.com.     59  IN  A   140.82.118.3
```

Parsed into the following json string:

```
{
    "command": {
        "string": "dig github.com +nostats",
        "version": "9.10.6"
    },
    "recordList": [
        {
            "host": "github.com.",
            "ttl": "59",
            "type": "A",
            "record": "140.82.118.4"
        },
        {
            "host": "github.com.",
            "ttl": "59",
            "type": "A",
            "record": "140.82.118.3"
        }
    ],
    "parser": {
        "name": "parse2Json",
        "version": "0.1.0",
        "rawInput": "\n; \u003c\u003c\u003e\u003e DiG 9.10.6 \u003c\u003c\u003e\u003e github.com +nostats\n;; global options: +cmd\n;; Got answer:\n;; -\u003e\u003eHEADER\u003c\u003c- opcode: QUERY, status: NOERROR, id: 58248\n;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n;; QUESTION SECTION:\n;github.com.\t\t\tIN\tA\n\n;; ANSWER SECTION:\ngithub.com.\t\t59\tIN\tA\t140.82.118.4\ngithub.com.\t\t59\tIN\tA\t140.82.118.3\n\n"
}
```

## Versioning

Versioning is based on [SemVer](http://semver.org/)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details
