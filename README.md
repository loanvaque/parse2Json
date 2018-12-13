# Parse 2 Json

Parsing of output files to json strings

## Process

1. Scan directory recursively
2. Find file names matching a pattern from a list of recognised patterns
3. Parse the content of the file according to the matched pattern
4. Convert the obtained elements to a json string
5. Save the json string to a file with the extenion ".json"

## File names

The names of the files to be parsed must contain one of the expected patterns\
Example: "github_ns_records**.dig.**txt"

The names of the output files will be the same as the names of the original files, appended with the extension ".json"\
Example: "github_ns_records.dig.txt**.json**"

## Regex patterns

File contents currently parseable:

- **nmap** (https://en.wikipedia.org/wiki/Nmap)
- **dig** (https://en.wikipedia.org/wiki/Dig_(command))

More regex patterns will be added according to personal needs or requests

## Parsing of file content

The recognised pattern in the file name indicates the regex to be aplied

Example:\
Output of a dig command:

```
; <<>> DiG 9.10.6 <<>> github.com +nostats
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21216
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;github.com.            IN  A

;; ANSWER SECTION:
github.com.     32  IN  A   140.82.118.4
github.com.     32  IN  A   140.82.118.3
```

Parsed into the following json string:

```
{
    "command": "dig github.com +nostats",
    "recordList": [
        {
            "host": "github.com.",
            "ttl": "32",
            "recordType": "A",
            "record": "140.82.118.4"
        },
        {
            "host": "github.com.",
            "ttl": "32",
            "recordType": "A",
            "record": "140.82.118.3"
        }
    ]
}
```

Saved in a file with the extension ".json"

## Versioning

Versioning is based on the RFC1035 recommendations for SOA RDATA format: YYYYMMDDnn\
Example: 2018121301 (year 2018, month 12, day 13, serial 01)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details
