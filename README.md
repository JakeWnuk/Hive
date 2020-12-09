<h1 align="center">
  Hive
  <br>
</h1>

[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/JakeWnuk/Hive/issues)
[![Python 3.9](https://img.shields.io/badge/Python-3.9-green)

Hive is a lightweight network enumeration tool designed for enumerating private ranges and single targets asynchronously and concurrently.

Developed and tested on Debian GNU distros.

## Demo

![Image](../master/static/demo.png?raw=true)


Hive works by first generating IP ranges for host discovery then divides the generated ranges into blocks of /24 addresses. Hive takes those ranges and assigns them to 'Drones,' which then sends ICMP packets to all hosts within a range. If any hosts are found within the range, the responsible Drone begins asynchronous enumeration. All drones act concurrently set to the maximum number of workers specified. Output is aggregated into a single folder with the scans, found ranges, and a easy to read csv.

![Image](../master/static/hive-target.png?raw=true)

Hive also has the ability to perform single target enumeration using common commands for port scanning and DNS reconnaissance. This information will be stored in its own folder for easy access.

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

## Installation

Download the repo.

```sh
▶ git clone https://github.com/JakeWnuk/Hive
```

Install the dependencies.

```sh
▶ pip3 install -r requirements.txt
```
