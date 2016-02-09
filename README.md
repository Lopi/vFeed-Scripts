# vFeed-Scripts
A python script utilizing the vFeed API to create a customized vulnerability threat feed based on your organization's technologies. Three files will be created after running the script.

1. vulns.json
2. nessus_scans.json
3. nmap_scans.json



## Example Output

```
-> % python threatfeed.py
Updating the vFeed database from your scripts
[+] Checking connectivity to http://www.toolswatch.org/vfeed/
[+] Checking for the latest vFeed Vulnerability Database
[+] Receiving 49 out of 49 Bytes of update (100 %)
[+] You have the latest vfeed.db Vulnerability Database
[+] Cleaning compressed database and update file
[+] Exporting to JSON file CVE_2015_1779.json
[!] CVE_2015_1779.json moved to export repository
[+] Exporting to JSON file CVE_2015_3943.json
[!] CVE_2015_3943.json moved to export repository
[+] Exporting to JSON file CVE_2015_3946.json
<..snip..>
```

## Sample nessus_scans.json output
```
-> % cat nessus_scans.json
[
    {
        "Exploits": {
            "Elliot D2": [],
            "ExploitDB": [],
            "Metasploit": [],
            "Saint": []
        },
        "Information": {
            "CAPEC": null,
            "CPE": [],
            "CVE": [
                {
                    "id": "CVE-2016-0502",
                    "modified": "2016-01-20T22:00:51.557-05:00",
                    "published": "2016-01-20T22:00:50.667-05:00",
                    "summary": "Unspecified vulnerability in Oracle MySQL 5.5.31 and earlier and 5.6.11 and earlier allows remote authenticated users to affect availability via unknown vectors related to Optimizer.",
                    "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0502"
                }
            ],
            "CWE": null,
            "Category": null
        },
        "Patches": {
            "Cisco": [],
            "Debian": [],
            "Fedora": [],
            "Gentoo": [],
            "HP": [],
            "IBM AIX Apar": [],
            "Mandriva": [],
            "Microsoft Bulletins": [],
            "Microsoft KB": [],
            "Redhat": [],
            "Suse": [],
            "Ubuntu": [],
            "Vmware": []
        },
        "References": {
            "BID": [],
            "CertVN": [],
            "IAVM": [],
            "OSVDB": [],
            "Other": {
                "References": [
                    {
                        "url": "http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html",
                        "vendor": "CONFIRM"
                    }
                ]
            },
            "SCIP": [
                {
                    "id": 80591,
                    "url": "http://www.scip.ch/?vuldb.80591"
                }
            ]
        },
        "Risk": [
            {
                "CVSS v2": [
                    {
                        "access complexity": "not_defined",
                        "access vector": "not_defined",
                        "authentication": "not_defined",
                        "availability impact": "not_defined",
                        "base": "not_defined",
                        "confidentiality impact": "not_defined",
                        "exploit": "not_calculated",
                        "impact": "not_calculated",
                        "integrity impact": "not_defined"
                    }
                ],
                "Top alert": false,
                "Top vulnerable": "Not Defined",
                "severity": "Not Defined"
            }
        ],
        "Rules": {
            "Snort": [],
            "Suricata": []
        },
        "Scanners": {
            "Nessus": [
                {
                    "family": "Databases",
                    "file": "mysql_5_5_32.nasl",
                    "id": "68938",
                    "name": "MySQL 5.5 < 5.5.32 Multiple Vulnerabilities"
                },
                {
                    "family": "Databases",
                    "file": "mysql_5_5_32_rpm.nasl",
                    "id": "88379",
                    "name": "Oracle MySQL 5.5.x < 5.5.32 Optimizer DoS (January 2016 CPU)"
                },
                {
                    "family": "Databases",
                    "file": "mysql_5_6_12.nasl",
                    "id": "68939",
                    "name": "MySQL 5.6.x < 5.6.12 Multiple Vulnerabilities"
                },
                {
                    "family": "Databases",
                    "file": "mysql_5_6_12_rpm.nasl",
                    "id": "88381",
                    "name": "Oracle MySQL 5.6.x < 5.6.12 Optimizer DoS (January 2016 CPU)"
                }
            ],
            "Nmap": [],
            "OpenVas": [],
            "Oval": []
        },
        "vFeed": {
            "Author": "NJ OUCHN",
            "Contact": "@toolswatch",
            "Product": "vFeed - The Correlated Vulnerability and Threat Database",
            "URL": "https://github.com/toolswatch/vFeed",
            "Version": "0.6.0",
            "id": "VFD-2016-0502"
        }
    },```
