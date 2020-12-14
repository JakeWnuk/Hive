<h1 align="center">
  <img src="static/hive-logo.png" alt="hive" width="125px"></a>
</h1>
<h1 align="center">
 Hive
 </h1>

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-blue.svg?style=flat)](https://github.com/JakeWnuk/Hive/issues)
[![Python 3.9](https://img.shields.io/badge/Python-3.9-blue)

**Hive** is a lightweight network enumeration tool designed for enumerating private/public ranges and single targets asynchronously and concurrently.

## Resources

-   [Features](#features)
-   [Usage](#usage)
-   [Output](#output)
-   [Installation](#installation)

## Features

#### Range Discovery and Enumeration 
![Image](../master/static/demo.png?raw=true)

**Hive** works by first generating IP ranges for host discovery then divides the generated ranges into blocks of addresses. **Hive** takes those ranges and assigns them to drones, which then sends ICMP packets to all hosts within a range. If any hosts are found within the range, the responsible drone begins asynchronous enumeration. All drones act concurrently set to the maximum number of workers specified. Output is aggregated into a single folder with the scans, found ranges, and a easy to read csv.

When doing discovery and enumeration the default mode is to scan and enumeration all private address ranges. This can be modified with the `-r` or `--range` flag to specify a given range. If enumeration is not desired and only host discovery should be performed this can be done with the `-n` or `--noscan` flag to prevent drones from starting enumeration.

**Hive** uses Nmap for enumeration and service detection the configuration of the scan can be modified within the code itself. The default settings are:

-   `nmap -n -T4 -sV -sU --top-ports 50 --max-retries 4 --host-timeout 45m  --script-timeout 45m`
-   `nmap -n -T4 -sV -sS --top-ports 50 --max-retries 4 --host-timeout 45m  --script-timeout 45m`


#### Single Target Enumeration
![Image](../master/static/hive-target.png?raw=true)

**Hive** also has the ability to perform single target enumeration using common commands for port scanning and DNS reconnaissance. This information will be stored in its own folder for easy access. **Hive** uses several commands to perform single target enumeration and many more can be added/edited within the code itself with minimal effort. The default scans are:
  
-   `host` to pull out IPv4 and IPv6 addresses routing information. 
-   `whois` to pull records in the databases maintained by several Network Information Centers (NICs).
-   `dig` to perform DNS lookups and display answers that are returned from the name server(s) that were queried.
-   `nmap -sS -T4 -Pn -p- --max-retries 4 --host-timeout 90m  --script-timeout 90m`
-   `nmap -sU -T4 -Pn --top-ports 1500 --max-retries 4 --host-timeout 90m  --script-timeout 90m`
-   Found ports will be passed to an NSE scan: 
    - `nmap -T4 -sSU -Pn -sC -sV --script vuln -p <PORTS> --max-retries 4 --host-timeout 90m  --script-timeout 90m`

**Hive** will then do basic checks on the pulled information to give feedback on the results for quick assessment. This mode is not designed to be the full extent of enumeration but rather aid in mass target selection. (Also great for CTFs)

#### Continous Discovery and Enumeration

**Hive** supports continous scanning with the `-c` or `--cycles` flag along with the `-s` or `--sleep` flag to begin scanning then sleep until the next round of scanning. **Hive* will report on found hosts, new hosts, and disappeared hosts then aggregated all of the resulting scans into a single result file showing when a host/port first appeared and was last seen.

## Output

**Hive** writes output to a folder, with no options it will write to the working directory but the output directory can be specified with `-o` or `--output`. The output is as following:

-   hive-output
    -   scans
        -   All nmap scans for every drone.
    -   target
        -   All output from `--target` function.
        -   When scanning multiple targets and the output directory is the same all scans aggregate here.
        -   To quickly search contents `find` can be very useful. `find . -name <FILE> -exec grep <REGEX> {} \;`
    -   cidr file
        -   File with all found IP's converted to CIDR ranges.
    -   hive-output.csv
        -   aggregated CSV file with the result of all scans.


## Usage

```sh
hive.py -h
```

This will display help for the tool. Here are all the options it supports.

|Flag |  Full Flag Option              | Description  |Example|
|-----|-------------------------|-------------------------------------------------------|-------------------------------|
|None | No flags set  | Scans private IP ranges for live hosts then enumerates them. Results are created in current working directory. |`hive.py`|
|-v | --verbosity |Increases the output verbosity. |`hive.py -v`|
|-t | --target  |Changes the mode to single target enumeration. |`hive.py -t 127.0.0.1`|
|-r | --range  |Scans a defined range for hosts then enumerates them. |`hive.py -r 10.0.0.0-10.255.255.255`|
|-n | --noscan  |Only looks for live hosts and does not perform enumeration. |`hive.py -n`|
|-o | --output  |Changes output location from cwd to specified directory.  |`hive.py -o ~/Desktop/`|
|-w | --workers  |Changes the number of max workers in the thread pool.   |`hive.py -w 20`|
|-c | --cycles   |Number of scan cycles to perform. Default is 1. | `hive.py -c 5`|
|-s | --sleep   |Number of minutes to sleep between scan cycles. Default is 60." | `hive -c 4 -s 30`|

## Installation

Download the repo.

```sh
▶ git clone https://github.com/JakeWnuk/Hive
```

Install the dependencies.

```sh
▶ pip3 install -r requirements.txt
```
