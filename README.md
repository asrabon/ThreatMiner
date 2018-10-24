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

<details><summary>Getting File Metadata (Input: MD5, SHA-1, or SHA-256)</summary>

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