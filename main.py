import asyncio
import concurrent.futures
import os
import time
from ipaddress import ip_address
import argparse
import re


async def gen_ip_range(start, end):
    """
    Generates IPv4 addresses inclusively
    :param start: start IPv4 address
    :param end:  end IPv4 address
    :return: list
    """
    printer("Generating buzz for " + str(start) + " - " + str(end), event=True)
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


def printer(msg, event=False, error=False, warn=False):
    class bcolors:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKCYAN = '\033[96m'
        OKGREEN = "\033[32m"
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

    tm = time.strftime("%H:%M:%S")

    if warn:
        print(f'{bcolors.WARNING}{bcolors.BOLD}[ * ] [{tm}] {msg}{bcolors.ENDC}')
    elif error:
        print(f'{bcolors.FAIL}[ ! ] [{tm}] {msg}{bcolors.ENDC}')
    elif event:
        print(f'{bcolors.OKGREEN}[ + ] [{tm}] {msg}{bcolors.ENDC}')
    else:
        print(f'{bcolors.OKCYAN}[ - ] [{tm}] {msg}{bcolors.ENDC}')


def parse_range(string):
    ip_rng = string.split("-")
    return [(ip_rng[0], ip_rng[1])]


async def run(cmd, return_stdout=False, do_print=False):
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
    Hive Jobs: creates the bees, operates the bees for scanning and enum, and aggregates the bees reports
    """

    def __init__(self, harvest=False, verbose=False, ip_range="", ip_target=""):

        if ip_target != "":
            printer("Starting recon and enumeration on " + str(ip_target) + "...", warn=True)
            asyncio.run(self._target_enum(ip_target, verbose))
            exit()

        if ip_range != "":
            self.SubnetList = ip_range
        else:
            self.SubnetList = [
                ("192.168.0.0", "192.168.255.255"), ("10.0.0.0", "10.255.255.255"), ("172.16.0.0", "172.16.255.255")]

        self.Bees = []
        try:
            asyncio.run(self._gen_bees(harvest, verbose))
        except ValueError:
            printer("Invalid range provided. Expected form like 10.0.0.0-10.255.255.255", error=True)
            exit()

    @staticmethod
    async def _target_enum(ip_target, verbose):
        stdout = await asyncio.gather(
            run(
                "host " + ip_target + " | tee host-" + ip_target + ".txt | grep address | grep -iv ipv6 | cut -d ' ' -f 4 | tee ipv4-" + ip_target + ".txt",
                return_stdout=True, do_print=verbose),
            run(
                "host " + ip_target + " | grep address | grep -i ipv6 | cut -d ' ' -f 5 | tee ipv6-" + ip_target + ".txt",
                return_stdout=True, do_print=verbose),
            run(
                "whois " + ip_target + " | tee whois-" + ip_target + ".txt | tr -cd '\11\12\15\40-\176'",
                return_stdout=True, do_print=verbose),
            run(
                "dig " + ip_target + " +nostats +nocomments +nocmd | tee dig-" + ip_target + ".txt | grep A | cut -d 'A' -f 2 | grep '.'",
                return_stdout=True, do_print=verbose),
            run(
                "nmap -sS -Pn -p- -oN ./basic-nmap-ss-" + ip_target + ".txt " + ip_target + " --resolve-all",
                return_stdout=True,
                do_print=verbose),
            run(
                "nmap -sU -Pn --top-ports 1000 -oN ./basic-nmap-su-" + ip_target + ".txt " + ip_target + " --resolve-all",
                do_print=verbose)
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
            "cat ./basic-nmap-s* | grep open | grep -iv filtered | cut -d '/' -f1 | sort -u | tee ./ports-" + ip_target + ".txt",
            return_stdout=True, do_print=verbose)

        # report
        printer("Found IPv4 Addresses: " + str(ipv4), warn=True)
        printer("Found IPv6 Addresses: " + str(ipv6), warn=True)
        ports = ports.split('\n')
        printer("Found Ports: " + str(ports), warn=True)
        port_str = ','.join([str(elem) for elem in ports])

        # kick off targeted NSE script
        await run(
            "nmap -sSU -Pn -sC -sV --script vuln -p " + port_str + " -oN ./targeted-nmap-ssu-" + ip_target + ".txt " + ip_target,
            do_print=verbose)

        try:
            if dig_ips != host_ips:
                printer("The dig and host command results do not align. Might be a LB.", warn=True)
            if "No match for" in stdout[2]:
                printer("No whois match found for given domain.", warn=True)
            if "0 hosts up" in stdout[4]:
                printer("Nmap failed to resolve a target for the given domain.", error=True)
        except ValueError:
            printer("Error when reviewing results!", error=True)

    async def _gen_bees(self, harvest, verbose):
        """
        Generates all the bees for the hive
        """

        ip_ranges = await asyncio.gather(
            *(gen_ip_range(itr[0], itr[1]) for itr in self.SubnetList)
        )
        for i in ip_ranges:
            split_ip_ranges = chunk_list(i, 256)
            for x in split_ip_ranges:
                self.Bees.append(Bee(x[0], x[-1], harvest, verbose))

    def operate(self):
        """
        Tells bee class to scan all of the given ranges with multi-threading and found targets are harvested
        """
        printer("! ! ! DEPLOYING SWARM ! ! !", warn=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
            executor.map(Bee.is_alive, self.Bees)

        live_bees = []
        for i in self.Bees:
            if i.get_status():
                live_bees.append(i)

        self.Bees = live_bees

    def report(self):
        printer("Hive Completed. Number of successful bees: " + str(len(self.Bees)), event=True)
        out_csv = ""
        for i in self.Bees:
            printer(str(i.get_range()[0]) + "/24", event=True)
            out_csv += str(i.get_harvest())

        string_match = '"IP";"FQDN";"PORT";"PROTOCOL";"SERVICE";"VERSION"'
        str1 = string_match
        out_csv = out_csv.replace(str1, "")
        out_csv = string_match + '\n' + out_csv

        with open("output-csv.txt", "w") as text_file:
            print(f"TotalAmount{out_csv}", file=text_file)
        printer("Hive has completed. Have a nice day :)", warn=True)


class Bee:
    """
    Bees are given an IP range to scan and then harvest IP's if their range has an alive IP address inside
    """

    def __init__(self, ip_start, ip_end, harvest=False, verbose=True):
        self.name = "Bee-" + str(ip_start) + "-" + str(ip_end)
        self.ipRange = (ip_start, ip_end)
        self.live = False
        self.harvest = harvest
        self.verbose = verbose
        self.enumResults = ""

    def get_status(self):
        """
        Bee reports if its range is alive
        :return: bool
        """
        return self.live

    def get_range(self):
        """
        Bee reports its assigned IP range
        :return: tuple
        """
        return self.ipRange

    def get_harvest(self):
        return self.enumResults

    def is_alive(self):
        """
        Tells if the Bee's assigned IP range has alive IP's inside
        """
        out = os.popen('fping -a -i 2 -r 4 -g ' + str(self.ipRange[0]) + '/24  2> /dev/null').read()

        if out == "":
            if self.verbose:
                printer("No buzz in... " + str(self.ipRange[0]) + " to " + str(self.ipRange[1]))
        else:
            printer("A bee found some flowers in... " + str(self.ipRange[0]) + " to " + str(self.ipRange[1]), warn=True)
            self.live = True
            if self.harvest:
                self._harvest()

    def _harvest(self):
        printer("Starting Nmap for " + self.name, event=True)
        out = os.popen(
            'nmap -n -Pn -sV -p 80,443,22,21,23 ' + str(
                self.ipRange[0]) + "-255 2>/dev/null | nmaptocsv 2>/dev/null").read()
        printer("Nmap finished for " + self.name, event=True)
        self.enumResults = out


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Network reconnaissance tool to discover hosts, ports, and perform basic recon.')
    parser.add_argument("-v", "--verbosity", action="store_true", default=False, help="increase output verbosity")
    parser.add_argument("-t", "--target", action="store", default=False,
                        help="Enumerates only one target. This will port scan!")
    parser.add_argument("-r", "--range", type=parse_range, action="store", default=False,
                        help="Enter an IP range instead of predefined private range")
    parser.add_argument("-n", "--noscan", action="store_false", default=True,
                        help="Only performs fping and no enumeration. Not valid with -t!")
    args = parser.parse_args()

    if args.target:
        myHive = Hive(harvest=args.noscan, verbose=args.verbosity, ip_target=args.target)
    elif args.range:
        myHive = Hive(harvest=args.noscan, verbose=args.verbosity, ip_range=args.range)
    else:
        myHive = Hive(harvest=args.noscan, verbose=args.verbosity)

    myHive.operate()
    myHive.report()
