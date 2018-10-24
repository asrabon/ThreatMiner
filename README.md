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