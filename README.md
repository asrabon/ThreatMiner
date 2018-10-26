# ThreatMiner
This library was made based upon ThreatMiner's API documentation page. https://www.threatminer.org/api.php

# Installation

```
pip install threatminer
```

# Usage

<details><summary>Creating a ThreatMiner Object</summary>

* Code

```
from threatminer import ThreatMiner

tm = ThreatMiner()
```
</details>

<br>

<details><summary>Getting Metadata Associated With a File (Input: MD5, SHA-1, or SHA-256)</summary>

* Code

    ```
    response = tm.get_metadata('e6ff1bf0821f00384cdd25efb9b1cc09')
    print(response)
    ```

* Output

    ```
    {
    "status_code": "200",
    "status_message": "Results found.",
    "results": [
        {
        "md5": "e6ff1bf0821f00384cdd25efb9b1cc09",
        "sha1": "16fd388151c0e73b074faa33698b9afc5c024b59",
        "sha256": "555b3689dec6ad888348c595426d112d041de5c989d4929284594d1e09f3d85f",
        "sha512": "7be8545c03f26192feb6eaf361b78b91966de28d2917ba1902508ad8589e0f0df748e82a265513f0426b50fedfda8fa6947c8b9e511b5d9a771ab20dc748367b",
        "ssdeep": "3072:HcRtvDzz/rup4/skvknm+GytbPlIyWYmxHznEt3xnDn/1iyG6mb2LoUEb:HEtvD7MkvVIpPlIjYQjQ3N/MV1AtE",
        "imphash": "dc73a9bd8de0fd640549c85ac4089b87",
        "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
        "architecture": "32 Bit",
        "authentihash": "f3ec83f9862e9b09203a21ddac5ecdc4f874a591c2b03ffc4d9a5749e4655e28",
        "file_name": "installaware.15-patch.exe",
        "file_size": "546304 bytes",
        "date_analysed": "2016-03-13 03:46:38"
        }
    ]
    }
    ```
</details>

<br>

<details><summary>Getting HTTP Traffic Associated With a File (Input: MD5, SHA-1, or SHA-256)</summary>

* Code

    ```
    response = tm.get_http_traffic('e6ff1bf0821f00384cdd25efb9b1cc09')
    print(response)
    ```

* Output
    ```
    {
    "status_code": "200",
    "status_message": "Results found.",
    "results": [
        {
        "http_traffic": [
            {
            "domain": "www.installaware.com",
            "source": "Hybrid-analysis",
            "url": "/",
            "ip": "209.222.0.52",
            "method": "GET",
            "raw": "GET / HTTP/1.1\nAccept: */*\nAccept-Language: en-us\nUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)\nAccept-Encoding: gzip, deflate\nHost: www.installaware.com\nConnection: Keep-Alive",
            "user_agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
            "port": ""
            },
            {
            "domain": "www.installaware.com",
            "source": "Hybrid-analysis",
            "url": "/installaware/2011/style.css",
            "ip": "209.222.0.52",
            "method": "GET",
            "raw": "GET /installaware/2011/style.css HTTP/1.1\nAccept: */*\nReferer: http://www.installaware.com/\nAccept-Language: en-US\nUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)\nAccept-Encoding: gzip, deflate\nHost: www.installaware.com\nConnection: Keep-Alive",
            "user_agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
            "port": ""
            }
        ]
        }]
    }
    ```

</details>

<br>

<details><summary>Getting Hosts Associated With a File (Input: MD5, SHA-1, or SHA-256)</summary>

* Code

    ```
    response = tm.get_hosts('e6ff1bf0821f00384cdd25efb9b1cc09')
    print(response)
    ```

* Output
    ```
    {
        "status_code": "200",
        "status_message": "Results found.",
        "results": [
            {
            "domains": [
                {
                "ip": "173.194.192.100",
                "domain": "www.google-analytics.com"
                },
                {
                "ip": "173.194.192.97",
                "domain": "www.googletagmanager.com"
                },
                {
                "ip": "216.58.216.106",
                "domain": "ajax.googleapis.com"
                },
                {
                "ip": "209.222.0.52",
                "domain": "www.installaware.com"
                },
                {
                "ip": "72.32.150.153",
                "domain": "installaware.app12.hubspot.com"
                },
                {
                "ip": "172.230.212.74",
                "domain": "js.hubspot.com"
                },
                {
                "ip": "74.125.135.156",
                "domain": "stats.g.doubleclick.net"
                }
            ],
            "hosts": [
                "209.222.0.52",
                "72.32.150.153"
            ]
            }
        ]
    }
    ```

</details>

<br>

<details><summary>Getting Mutants Associated With a File (Input: MD5, SHA-1, or SHA-256)</summary>

* Code

    ```
    response = tm.get_mutants('e6ff1bf0821f00384cdd25efb9b1cc09')
    print(response)
    ```

* Output
    ```
    {
        "status_code": "200",
        "status_message": "Results found.",
        "results": [
            {
            "mutants": [
                "\"\\Sessions\\1\\BaseNamedObjects\\Local\\MidiMapper_modLongMessage_RefCnt\"",
                "\"\\Sessions\\1\\BaseNamedObjects\\Local\\!IETld!Mutex\""
            ]
            }
        ]
    }
    ```

</details>

<br>

<details><summary>Getting AV Detections Associated With a File (Input: MD5, SHA-1, or SHA-256)</summary>

* Code

    ```
    response = tm.get_av_detections('e6ff1bf0821f00384cdd25efb9b1cc09')
    print(response)
    ```

* Output
    ```
    {
        "status_code": "200",
        "status_message": "Results found.",
        "results": [
            {
            "av_detections": [
                {
                "detection": "Trojan.Generic.8175716",
                "av": "MicroWorld-eScan"
                },
                {
                "detection": "Trojan-Spy.Win32.Hoardy!O",
                "av": "CMC"
                },
                {
                "detection": "TrojanAPT.Infostealer.H4",
                "av": "CAT-QuickHeal"
                },
                {
                "detection": "Spyware.Infostealer.Flea.APT",
                "av": "ALYac"
                },
                ...
                {
                "detection": "HEUR/Malware.QVM09.Gen",
                "av": "Qihoo-360"
                }
            ]
            }
        ]
    }
    ```

</details>

<br>

<details><summary>Getting Associated Reports (Input: MD5, SHA-1, SHA-256, SSDeep, IP, Domain, URL)</summary>

* Code

    ```
    response = tm.get_report('vwrm.com')
    print(response)
    ```

* Output
    ```
    {
        "status_code": "200",
        "status_message": "Results found.",
        "results": [
            {
            "filename": "comment_crew_indicators_of_compromise.pdf",
            "year": "2013",
            "URL": "https://www.threatminer.org/report.php?q=comment_crew_indicators_of_compromise.pdf&y=2013"
            }
        ]
    }
    ```

</details>

<br>

<details><summary>Getting Associated Samples (Input: IP, Domain)</summary>

* Code

    ```
    response = tm.get_related_samples('216.58.213.110')
    print(response)
    ```

* Output
    ```
    {
        "status_code": "200",
        "status_message": "Results found.",
        "results": [
            "dd0418c01b7196e967a63fedda70eaf6de4fffb5296a24b9ec13f7a09c2f7bc1",
            "abf736e1a8e0508b6dd840b012d4231cf13f8b48c2dcb3ed18ce92a59dba7109",
            "66e2a31fe008a463431b9ef0ffdf1de1706626d30776de2ec861d11e498e023c",
            "3cb694866d37274dcc0e46aaa20a45d55f4c8de6798e1226898776ea202162bf",
            "cdb4f8bc40e72cc3cc9ec9b0636f36a01ce38bdc7e0cf1e1df6adfdf6e7d71ee",
            "c40c320267f90b4f66dfff2b10db450d12d88cba7c488c09fbe55360742c828e",
            "694f36b9d133e602c946caa49c42c3cf77d6f94405aba8924f9b6a21a42fc12a",
            "6dc6249419f0e10aaacb513f9411a73f9da2c694727cc53c1883f176c5d5811f",
            "94a2a98ca3e9fd5d48ddc86abf19979b99c31370dbbf286a709ad13829dc35ea",
            "914fc30ab1ae8920812bf87037e18ef06eed5f3327e9aa43d9e9e933455c9a3c",
            "b9a6350fb3ff6bc1a567be2689b4763245214782fd09a39a1dced29ef63ae447",
            "161897e4f2447cc01e2efaa58d8fbfb09eeee02902a2ef666bdf8239c13cd590"
        ]
    }
    ```

</details>

<br>

<details><summary>Get "Who Is" Information (Input: IP, Domain)</summary>

* Code

    ```
    response = tm.who_is('vwrm.com')
    print(response)
    ```

* Output
    ```
    {
        "status_code": "200",
        "status_message": "Results found.",
        "results": [
            {
            "domain": "vwrm.com",
            "is_subdomain": false,
            "root_domain": "",
            "whois": {
                "updated_date": "2012-03-26 12:04:11",
                "whois_md5": "f8c433f165d39ce655c18e91d685cca0",
                "billing_info": {
                "Organization": " Aliant Telecom",
                "City": " Saint John",
                "State": " New Brunswick",
                "Country": " Canada",
                "Postal_Code": " E2L4K2"
                },
                "registrant_info": {
                "City": " Kentville",
                "Country": " Canada",
                "State": " Nova Scotia",
                "Street": " PO Box 895",
                "Postal_Code": " B4N4H8",
                "Organization": " Valley Waste Resource Management"
                },
                "creation_date": "1999-04-01 05:00:00",
                "whois_server": "whois.register.com",
                "emails": {
                "admin": "",
                "tech": "",
                "registrant": "",
                "billing": ""
                },
                "tech_info": {
                "Organization": " Aliant Telecom",
                "City": " Saint John",
                "State": " New Brunswick",
                "Country": " Canada",
                "Postal_Code": " E2L4K2"
                },
                "admin_info": {
                "Organization": " Aliant Telecom",
                "City": " Saint John",
                "State": " New Brunswick",
                "Country": " Canada",
                "Postal_Code": " E2L4K2"
                },
                "nameservers": [
                "onyx.nbnet.nb.ca",
                "opal.nbnet.nb.ca"
                ],
                "expiration_date": "2017-04-01 04:00:00",
                "email_hashes": {
                "admin": "",
                "tech": "",
                "registrant": "",
                "billing": ""
                },
                "registrar": "register.com, inc.",
                "date_checked": "2016-11-22 14:10:14",
                "reg_info": {
                "Organization": " Aliant Telecom",
                "City": " Saint John",
                "State": " New Brunswick",
                "Country": " Canada",
                "Postal_Code": " E2L4K2"
                }
            },
            "last_updated": "2016-01-16 00:00:00"
            }
        ]
    }
    ```

</details>

<br>

<details><summary>Getting DNS Info (Input: IP, Domain)</summary>

* Code

    ```
    response = tm.passive_dns('vwrm.com')
    print(response)
    ```

* Output
    ```
    {
        "status_code": "200",
        "status_message": "Results found.",
        "results": [
            {
            "ip": "209.29.221.235",
            "first_seen": "2013-09-19 00:00:00",
            "last_seen": "2016-02-01 09:41:15"
            }
        ]
    }
    ```

</details>

<br>

<details><summary>Getting All URIs (Input: Domain)</summary>

* Code

    ```
    response = tm.get_uris('vwrm.com')
    print(response)
    ```

* Output
    ```
    {
        "status_code": "200",
        "status_message": "Results found.",
        "results": [
            {
            "domain": "vwrm.com",
            "ip": "",
            "uri": "http://vwrm.com/maps/iexplorer.zip",
            "last_seen": "2014-07-17 16:51:28"
            },
            {
            "domain": "vwrm.com",
            "ip": "",
            "uri": "http://vwrm.com/",
            "last_seen": "2013-04-23 18:48:53"
            }
        ]
    }
    ```

</details>

<br>

<details><summary>Getting Subdomains (Input: Domain)</summary>

* Code

    ```
    response = tm.get_subdomains('vwrm.com')
    print(response)
    ```

* Output
    ```
    {
        "status_code": "200",
        "status_message": "Results found.",
        "results": [
            "www.vwrm.com",
            "mail.vwrm.com"
        ]
    }
    ```

</details>
