#!/usr/bin/python3

#
#   Network reconnaissance tool for endpoint enumeration.
#   Developers assume no liability and are not responsible for any misuse or damage.
#

import argparse
import asyncio
import concurrent.futures
import os
import re
import time
from io import StringIO
from ipaddress import ip_address

import pandas as pd


async def gen_ip_range(start, end):
    """
    Generates IPv4 addresses inclusively
    :param start: start IPv4 address
    :param end:  end IPv4 address
    :return: list of ips
    """
    printer("Generating drones for " + str(start) + "-" + str(end), event=True)
    start_int = int(ip_address(start).packed.hex(), 16)
    end_int = int(ip_address(end).packed.hex(), 16)
    return [ip_address(ip).exploded for ip in range(start_int, end_int)]


def chunk_list(lst, n):
    """
    Splits a list into n parts
    :param lst: list obj
    :param n: parts int
    :return: list of lists
    """
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def printer(msg, intro=False, event=False, error=False, warn=False, end=False):
    """
    Prints formatted text to CLI
    :param end: ending message
    :param intro: start message
    :param msg: string to be displayed
    :param event: bool changes visual for events
    :param error: bool changes visual for errors
    :param warn: bool changes visual for warnings
    """

    class colors:
        BLINK = '\033[5m'
        OKBLUE = '\033[94m'
        OKCYAN = '\033[96m'
        OKGREEN = "\033[32m"
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'

    tm = time.strftime("%H:%M:%S")

    if intro:
        print(
            f'{colors.OKBLUE}{colors.BOLD} {msg}{colors.ENDC}')
    elif end:
        print(f'{colors.BLINK}{colors.OKBLUE}{colors.BOLD}[ # ] [{tm}] {msg}{colors.ENDC}')
    elif warn:
        print(f'{colors.WARNING}{colors.BOLD}[ * ] [{tm}] {msg}{colors.ENDC}')
    elif error:
        print(f'{colors.FAIL}[ ! ] [{tm}] {msg}{colors.ENDC}')
    elif event:
        print(f'{colors.OKGREEN}[ + ] [{tm}] {msg}{colors.ENDC}')
    else:
        print(f'{colors.OKCYAN}[ - ] [{tm}] {msg}{colors.ENDC}')


def parse_range(string):
    """
    Parses IP range for args parser
    :param string: formatted string X.X.X.X-Y.Y.Y.Y
    :return: tuple of range
    """
    ip_rng = string.split("-")
    return [(ip_rng[0], ip_rng[1])]


async def run(cmd, return_stdout=False, do_print=False):
    """
    Function used for asyncio to interact with OS
    :param cmd: command to run
    :param return_stdout: bool self explanatory
    :param do_print: bool for printing to CLI
    :return: if stdout ascii decoded string
    """
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    stdout, stderr = await proc.communicate()
    if proc.returncode == 0 and do_print:
        printer(f"{cmd!r} exited with {proc.returncode}", event=True)
    elif do_print:
        printer(f"{cmd!r} exited with {proc.returncode}", error=True)
    if return_stdout:
        return stdout.decode('ascii').rstrip()


class Hive:
    """
    Hive Jobs: creates the drones, operates the drones for scanning and enum, and aggregates the drones reports
    """

    def __init__(self, harvest=False, verbose=False, ip_range="", ip_target="", work_dir="", threads=50):
        """
        :param harvest: bool to run enumeration scan on found ips
        :param verbose: bool for verbosity
        :param ip_range: used in args parser to run a range instead of private range
        :param ip_target: used in args parser to enum a target rather than host discovery
        :param work_dir: working directory for results
        """
        self.harvest = harvest
        self.verbose = verbose
        self.ip_range = ip_range
        self.ip_target = ip_target
        self.wd = work_dir
        self.Drones = []
        self.threads = threads

        printer('''
        ██╗  ██╗██╗██╗   ██╗███████╗
        ██║  ██║██║██║   ██║██╔════╝
        ███████║██║██║   ██║█████╗  
        ██╔══██║██║╚██╗ ██╔╝██╔══╝  
        ██║  ██║██║ ╚████╔╝ ███████╗
        ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝
        ''', intro=True)
        printer("NUMBER OF CURRENT WORKERS: " + str(threads), warn=True)

        if ip_target != "":
            asyncio.run(self._target_enum())
            exit()

        if ip_range != "":
            # check last octet for ranges
            if int(ip_range[0][0][-1]) == 0 and int(ip_range[0][1][-3:]) == 255:
                self.subnet_list = ip_range
            else:
                printer("Sorry Hive can only scan ranges with the 4th octect being 0 or 255", error=True)
                exit()
        else:
            self.subnet_list = [
                ("192.168.0.0", "192.168.255.255"), ("172.16.0.0", "172.31.255.255"), ("10.0.0.0", "10.255.255.255")]

        try:
            asyncio.run(self._gen_drones())
        except ValueError:
            printer("Invalid range provided. Expected form like 10.0.0.0-10.255.255.255", error=True)
            exit()

    async def _target_enum(self):
        """
        Function used for single target enumeration
        """
        printer("Starting recon and enumeration on " + str(self.ip_target) + "...", warn=True)
        stdout = await asyncio.gather(
            run(
                "host " + self.ip_target + " | tee " + self.wd + "/target/host-" + self.ip_target +
                ".txt | grep address | grep -iv ipv6 | cut -d ' ' -f 4 | tee " + self.wd + "/target/ipv4-" +
                self.ip_target + ".txt",
                return_stdout=True, do_print=self.verbose),
            run(
                "host " + self.ip_target + " | grep address | grep -i ipv6 | cut -d ' ' -f 5 | tee " + self.wd +
                "/target/ipv6-" + self.ip_target + ".txt",
                return_stdout=True, do_print=self.verbose),
            run(
                "whois " + self.ip_target + " | tee " + self.wd + "/target/whois-" + self.ip_target +
                ".txt | tr -cd '\11\12\15\40-\176'",
                return_stdout=True, do_print=self.verbose),
            run(
                "dig " + self.ip_target + " +nostats +nocomments +nocmd | tee " + self.wd + "/target/dig-" +
                self.ip_target + ".txt | grep A | cut -d 'A' -f 2 | grep '.'",
                return_stdout=True, do_print=self.verbose),
            run(
                "nmap -sS -T4 -Pn --top-ports 3400 -oN " + self.wd + "/target/basic-nmap-ss-" + self.ip_target +
                ".txt " + self.ip_target + " --max-retries 4 --host-timeout 15m  --script-timeout 10m",
                return_stdout=True,
                do_print=self.verbose),
            run(
                "nmap -sU -T4 -Pn --top-ports 1500 -oN " + self.wd + "/target/basic-nmap-su-" + self.ip_target +
                ".txt " + self.ip_target + " --max-retries 4 --host-timeout 15m  --script-timeout 10m",
                do_print=self.verbose)
        )

        # get results of host and dig to make sure they align for ipv4
        dig_ips = re.sub(r'\t', '', stdout[3]).split('\n')
        host_ips = stdout[0].split('\n')
        dig_ips.sort()
        host_ips.sort()

        # use information to build profile
        ipv4 = stdout[0].split('\n')
        ipv6 = stdout[1].split('\n')

        # read the nmap results for a port list
        ports = await run(
            "cat " + self.wd + "/target/basic-nmap-s*-" + self.ip_target +
            ".txt | grep open | grep -iv filtered | cut -d '/' -f1 | sort -u | tee " + self.wd +
            "/target/ports-" + self.ip_target + ".txt",
            return_stdout=True, do_print=self.verbose)

        # report findings
        printer("Found IPv4 Addresses: " + str(ipv4), event=True)
        printer("Found IPv6 Addresses: " + str(ipv6), event=True)
        ports = ports.split('\n')
        printer("Found Ports: " + str(ports), event=True)
        port_str = ','.join([str(elem) for elem in ports])

        # kick off targeted NSE script
        await run(
            "nmap -T4 -sSU -Pn -sC -sV --script vuln -p " + port_str + " -oN " + self.wd + "/target/vuln-nmap-ssu-" +
            self.ip_target + ".txt --max-retries 4 --host-timeout 15m  --script-timeout 10m" + self.ip_target,
            do_print=self.verbose)

        # check results
        try:
            if dig_ips != host_ips:
                printer("The dig and host command results do not align. Might be a LB.", warn=True)
            if "No match for" in stdout[2]:
                printer("No whois match found for given domain.", warn=True)
            if "0 hosts up" in stdout[4]:
                printer("Nmap failed to resolve a target for the given domain.", error=True)
        except ValueError:
            printer("Error when reviewing results!", error=True)

        printer("Hive has completed. Have a nice day.", end=True)

    async def _gen_drones(self):
        """
        Generate drone objects for the hive
        """
        ip_ranges = await asyncio.gather(
            *(gen_ip_range(itr[0], itr[1]) for itr in self.subnet_list)
        )
        for i in ip_ranges:
            split_ip_ranges = chunk_list(i, 256)
            for x in split_ip_ranges:
                self.Drones.append(Drone(x[0], x[-1], x, self.wd, self.harvest, self.verbose))

    def operate(self):
        """
        Tells drone class to scan all of the given ranges with multi-threading and found targets are enumerated
        """
        printer("! ! ! DEPLOYING SWARM ! ! !", warn=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=int(self.threads)) as executor:
            executor.map(Drone.is_alive, self.Drones)

        live_drones = []
        for i in self.Drones:
            if i.get_status():
                live_drones.append(i)

        self.Drones = live_drones

    def report(self):
        """
        Collects the results from the drones and prints them to CLI and files
        """
        printer("Number of successful drones: " + str(len(self.Drones)), warn=True)
        out_csv = ""
        out_subs = ""
        for i in self.Drones:
            printer(str(i.get_range()[0]) + "-" + str(i.get_range()[1]))
            out_csv += str(i.get_harvest())
            out_subs += str(i.get_range()[0]) + "-" + str(i.get_range()[1]) + "\n"

        # aggregate results
        string_match = '"IP";"FQDN";"PORT";"PROTOCOL";"SERVICE";"VERSION"'
        str1 = string_match
        out_csv = out_csv.replace(str1, "")
        out_csv = string_match + '\n' + out_csv
        file_str = StringIO(out_csv)
        df = pd.read_csv(file_str, sep=";")
        df.dropna(subset=["PORT"], inplace=True)
        df.drop(columns=["FQDN"], inplace=True)
        df.set_index("IP", inplace=True)
        df.to_csv(self.wd + "/hive-output.csv")

        with open(self.wd + "/subs.txt", "w") as text_file:
            print(f"Found Subs: \n{out_subs}", file=text_file)

        printer("Hive has completed. Have a nice day.", end=True)


class Drone:
    """
    Drones are given an IP range to scan and then harvest IP's if their range has an alive IP address inside
    """

    def __init__(self, ip_start, ip_end, ip_list, work_dir, harvest=False, verbose=True):
        self.name = "Drone-" + str(ip_start) + "-" + str(ip_end)
        self.ipRange = (ip_start, ip_end)
        self.ipList = ip_list
        self.live = False
        self.harvest = harvest
        self.verbose = verbose
        self.enumResults = ""
        self.wd = work_dir

    def get_status(self):
        """
        Drone reports if its range is alive
        :return: bool
        """
        return self.live

    def get_range(self):
        """
        Drone reports its assigned IP range
        :return: tuple
        """
        return self.ipRange

    def get_harvest(self):
        """
        Drone returns results of enumeration
        :return: string
        """
        return self.enumResults

    def is_alive(self):
        """
        Tells if the Drone's assigned IP range has alive IP's inside
        """

        out = os.popen(
            'fping -a -i 1 -r 1 -g ' + str(self.ipRange[0]) + ' ' + str(self.ipRange[1]) + ' 2> /dev/null').read()

        if out == "":
            if self.verbose:
                printer("Nothing in " + str(self.ipRange[0]) + " to " + str(self.ipRange[1]))
        else:
            printer("A drone discovered " + str(self.ipRange[0]) + " to " + str(self.ipRange[1]), event=True)
            self.live = True
            if self.harvest:
                self._harvest()

    def _harvest(self):
        """
        Drone starts enumeration on it's range
        """
        printer("Starting Nmap for " + self.name)
        std_out = os.popen(
            '(nmap -n -T4 -sV -sU --top-ports 20 ' +
            str(self.ipRange[0]) +
            '/24 --max-retries 4 --host-timeout 15m  --script-timeout 10m -oN ' + self.wd + '/scans/nmap-su-' +
            self.name + '.txt 2>/dev/null &' +
            'nmap -n -T4 -Pn -sV -sS --top-ports 20 ' +
            str(self.ipRange[0]) +
            '/24 --max-retries 4 --host-timeout 15m  --script-timeout 10m -oN ' + self.wd + '/scans/nmap-ss-' +
            self.name + '.txt 2>/dev/null) | nmaptocsv 2>/dev/null').read()

        printer("Nmap finished for " + self.name, event=True)
        self.enumResults = std_out


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Network reconnaissance tool to discover hosts, ports, and perform targeted recon.')
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("-v", "--verbosity", action="store_true", default=False, help="Increase output verbosity.")
    group.add_argument("-t", "--target", action="store", default=False,
                       help="Enumerates only one target. This will port scan!")
    group.add_argument("-r", "--range", type=parse_range, action="store", default=False,
                       help="Enter an IP range instead of predefined private range. Separate with '-'.")
    parser.add_argument("-n", "--noscan", action="store_false", default=True,
                        help="Only performs fping and no enumeration. Does not affect --target.")
    parser.add_argument("-o", "--output", action="store", default=os.getcwd(), help="Output directory. Default is cwd.")
    parser.add_argument("-w", "--workers", action="store", default=50,
                        help="Max workers for ThreadPoolExecutor. Edit with caution. Default is 50.")
    args = parser.parse_args()

    # confirm top directory exists; if not, populate it
    wd = os.path.join(args.output, "hive-results")
    if not os.path.exists(wd):
        os.makedirs(wd, exist_ok=True)
        os.makedirs(os.path.join(wd, "target"), exist_ok=True)
        os.makedirs(os.path.join(wd, "scans"), exist_ok=True)

    # kick off
    if args.target:
        myHive = Hive(harvest=args.noscan, verbose=args.verbosity, ip_target=args.target, work_dir=wd,
                      threads=args.threads)
    elif args.range:
        myHive = Hive(harvest=args.noscan, verbose=args.verbosity, ip_range=args.range, work_dir=wd,
                      threads=args.threads)
    else:
        myHive = Hive(harvest=args.noscan, verbose=args.verbosity, work_dir=wd, threads=args.threads)

    myHive.operate()
    myHive.report()
