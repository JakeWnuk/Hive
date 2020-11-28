<h1 align="center">
  <img src="static/logo_sm.png" alt="nuclei" width="200px"></a>
  <br>
</h1>

[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/JakeWnuk/Hive/issues)
[![made-with-python](http://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)

Hive is a simple network enumeration tool designed for enumerating private ranges and single targets asynchronously.

## Demo

<img src="https://raw.githubusercontent.com/JakeWnuk/Hive/master/static/demo.png" alt="" height=443 width=666px>
Hive by default scans in /24 blocks for hosts.

## Usage

```sh
hive.py -h
```

This will display help for the tool. Here are all the options it supports.

|Flag |  Full Flag                   |Description  |Example|
|-----|-----------------------|-------------------------------------------------------|-------------------------------|
|Default |Scans private IP ranges for live hosts then enumerates them. Results are created in current working directory.    |hive.py|
|-v | --verbosity        |Increases the output verbosity.    |hive.py -v|
|-t | --target |Changes the mode to single target enumeration.               |hive.py -t 127.0.0.1|
|-r | --range        |Scans a defined range for hosts then enumerates them.    |hive.py -r 10.0.0.0-10.255.255.255|
|-n | --noscan |Only looks for live hosts and does not perform enumeration.               |hive.py -n|
|-o | --output        |Changes output location from cwd to specified directory.    |hive.py -o ~/Desktop/|
|-th | --threads |Changes the number of max workers in the thread pool.               |hive.py -th 20|

## Installation

Download the repo.

```sh
▶ git clone https://github.com/JakeWnuk/Hive.git
```

Install the dependencies.

```sh
▶ pip3 install -r requirements.txt
```
