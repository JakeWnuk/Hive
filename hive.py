#!/usr/bin/python3.9

#
#   Network reconnaissance tool for endpoint enumeration.
#   Developers assume no liability and are not responsible for any misuse or damage.
#

import argparse
import asyncio
import concurrent.futures
import datetime as dt
import ipaddress
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
    message("Generating drones for " + str(start) + "-" + str(end), event=True)
    start_int = int(ip_address(start).packed.hex(), 16)
    end_int = int(ip_address(end).packed.hex(), 16)
    return [ip_address(ip).exploded for ip in range(start_int, end_int)]


def dep_check():
    """
    Checks for bash dependencies
    """
    if not os.path.exists('/usr/bin/fping'):
        message("Missing dependency fping!", error=True)
        exit()
    elif not os.path.exists('/usr/bin/nmap'):
        message("Missing dependency nmap!", error=True)
        exit()


def chunk_list(lst, n):
    """
    Splits a list into n parts
    :param lst: list obj
    :param n: parts int
    :return: list of lists
    """
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def message(msg, intro=False, event=False, error=False, warn=False, end=False):
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
        FAIL = '\033[31m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'

    tm = time.strftime("%H:%M:%S")

    if intro:
        print(
            f'{colors.OKBLUE}{colors.BOLD}{msg}{colors.ENDC}')
    elif end:
        print(f'{colors.OKBLUE}{colors.BOLD}[ # ] [{tm}] {msg}{colors.ENDC}')
    elif warn:
        print(f'{colors.WARNING}{colors.BOLD}[ * ] [{tm}] {msg}{colors.ENDC}')
    elif error:
        print(f'{colors.FAIL}[ ! ] [{tm}] {colors.ENDC}{msg}')
    elif event:
        print(f'{colors.OKGREEN}[ + ] [{tm}] {colors.ENDC}{msg}')
    else:
        print(f'{colors.OKCYAN}[ - ] [{tm}] {colors.ENDC}{msg}')


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
        message(f"{cmd!r} exited with {proc.returncode}", event=True)
    elif do_print:
        message(f"{cmd!r} exited with {proc.returncode}", error=True)
    if return_stdout:
        return stdout.decode('ascii').rstrip()


def report_cidr(wrk_dir, df):
    """
    Prints a file with ips in CIDR format
    :param wrk_dir: working directory to write
    :param df: pd.DataFrame of hive output
    """
    out_file = ""
    ip_lst = set(df.IP.unique().tolist())
    nets = [ipaddress.ip_network(ip) for ip in ip_lst]
    cidr = list(ipaddress.collapse_addresses(nets))
    for i in cidr:
        out_file += format(i) + '\n'

    with open(wrk_dir + "/cidr.txt", "w") as text_file:
        print(f"{out_file}", file=text_file)


def sleepy(minutes):
    """
    Used in cycle to control sleep time
    :param minutes: minutes to sleep
    """
    tm = time.strftime("%H:%M:%S")
    message('Sleeping until ' + str(
        (dt.datetime.strptime(tm, "%H:%M:%S") + dt.timedelta(minutes=int(minutes))).strftime("%H:%M:%S")), warn=True)
    time.sleep((int(minutes) * 60))


def cycle(hive, sleep, itr):
    """
    Controls how many scan cycles to perform
    :param hive: hive class
    :param sleep: int of min to sleep
    :param itr: number of times to scan
    """
    try:
        master_df = pd.DataFrame()
        for i in range(int(itr)):
            hive.operate()
            df = hive.report()

            if i == 0:
                master_df = df
                master_df['FIRST SEEN'] = dt.datetime.now().strftime("%H:%M:%S")
                master_df['LAST SEEN'] = ''
                # sleep for given minutes
                sleepy(sleep)
            else:
                new_df = \
                    master_df.merge(df, how='outer', on=['IP', 'PORT', 'PROTOCOL', 'SERVICE', 'VERSION'],
                                    indicator=True).loc[
                        lambda x: x['_merge'] == 'right_only']
                new_df.drop(columns=['_merge'], inplace=True)
                new_df['FIRST SEEN'] = dt.datetime.now().strftime("%H:%M:%S")

                # check for new hosts before append then check for removed
                new_ips = list(set(df.IP.unique().tolist()) - set(master_df.IP.unique().tolist()))
                master_df = master_df.append(new_df)
                rm_ips = list(set(master_df.IP.unique().tolist()) - set(df.IP.unique().tolist()))

                for x in rm_ips:
                    master_df.loc[(master_df['IP'] == x) & (
                        master_df['LAST SEEN'].isnull()), 'LAST SEEN'] = dt.datetime.now().strftime("%H:%M:%S")

                if not new_ips:
                    pass
                else:
                    message('New hosts found: \n' + str(new_ips), event=True)

                if not rm_ips:
                    pass
                else:
                    message('Ghosted hosts: \n' + str(rm_ips), error=True)

                # write output
                report_cidr(wd, master_df)
                master_df.reset_index(drop=True, inplace=True)
                master_df.to_csv(wd + "/hive-output.csv")

                if i + 1 != int(itr):
                    message('Finished cycle ' + str(i + 1) + '/' + str(itr))
                    # sleep for given minutes
                    sleepy(sleep)
                else:
                    message('Finished cycle ' + str(i + 1) + '/' + str(itr))
                    message("Hive has completed. Have a nice day.", end=True)

    except KeyboardInterrupt:
        message("Stopping Hive!", warn=True)


class Hive:
    """
    Hive Jobs: creates the drones, operates the drones for scanning and enum, and aggregates the drones reports
    """

    def __init__(self, harvest=False, verbose=False, ip_range="", ip_target="", work_dir="", workers=32, ports=50):
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
        self.workers = int(workers)
        self.ports = int(ports)

        message('''       __ ___         
      / // (_)  _____ 
     / _  / / |/ / -_)
    /_//_/_/|___/\__/  v1.0
''', intro=True)
        message("NUMBER OF WORKERS: " + str(self.workers), warn=True)

        if ip_range != "":
            # check last octet for ranges
            if int(ip_range[0][0][-1]) == 0 and int(ip_range[0][1][-3:]) == 255:
                self.subnet_list = ip_range
            else:
                message("Sorry Hive can only scan ranges with the 4th octect being 0 or 255", error=True)
                exit()
        else:
            self.subnet_list = [("192.168.0.0", "192.168.255.255"),
                                ("172.16.0.0", "172.31.255.255"), ("10.0.0.0", "10.255.255.255")]

        try:
            asyncio.run(self._gen_drones())
        except ValueError:
            message("Invalid range provided. Expected form like 10.0.0.0-10.255.255.255", error=True)
            exit()

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
                self.Drones.append(Drone(x[0], x[-1], x, self.wd, self.harvest, self.verbose, self.ports))

    def operate(self):
        """
        Tells drone class to scan all of the given ranges with multi-threading and found targets are enumerated
        """
        message("Deploying swarm!", warn=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=int(self.workers)) as executor:
            try:
                executor.map(Drone.is_alive, self.Drones)
            except KeyboardInterrupt:
                message("Stopping Hive!", warn=True)
                executor.shutdown(wait=False, cancel_futures=True)

        live_drones = []
        for i in self.Drones:
            if i.get_status():
                live_drones.append(i)

        self.Drones = live_drones

    def report(self):
        """
        Collects the results from the drones and prints them to CLI and files
        """
        message("Number of successful drones: " + str(len(self.Drones)), warn=True)
        out_csv = ""

        for i in self.Drones:
            out_csv += str(i.get_harvest())

        # aggregate results
        string_match = '"IP";"FQDN";"PORT";"PROTOCOL";"SERVICE";"VERSION"'
        str1 = string_match
        out_csv = out_csv.replace(str1, "")
        out_csv = string_match + '\n' + out_csv
        file_str = StringIO(out_csv)
        df = pd.read_csv(file_str, sep=";")
        df.dropna(subset=["PORT"], inplace=True)
        df.drop(columns=["FQDN"], inplace=True)
        message("Number of hosts found: " + str(len(df["IP"].unique())), warn=True)

        df.reset_index(drop=True, inplace=True)
        df.to_csv(self.wd + "/hive-output.csv")
        report_cidr(self.wd, df)

        message("Hive has completed. Have a nice day.", end=True)

        return df


class Drone:
    """
    Drones are given an IP range to scan and then harvest IP's if their range has an alive IP address inside
    """

    def __init__(self, ip_start, ip_end, ip_list, work_dir, harvest=False, verbose=True, ports=50):
        self.name = "Drone-" + str(ip_start) + "-" + str(ip_end)
        self.ipRange = (ip_start, ip_end)
        self.ipList = ip_list
        self.live = False
        self.harvest = harvest
        self.verbose = verbose
        self.enumResults = ""
        self.wd = work_dir
        self.ports = int(ports)

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
                message("Nothing in " + str(self.ipRange[0]) + " to " + str(self.ipRange[1]))
        else:
            message("A drone discovered " + str(self.ipRange[0]) + " to " + str(self.ipRange[1]), event=True)
            self.live = True
            if self.harvest:
                self._harvest()

    def _harvest(self):
        """
        Drone starts enumeration on it's range
        """
        message("Starting Nmap for " + self.name)
        std_out = os.popen(
            '{ nmap -n -T4 -sV -sU --top-ports ' + str(self.ports) + ' ' +
            str(self.ipRange[0]) +
            '/24 --max-retries 4 --host-timeout 45m  --script-timeout 45m -oN ' + self.wd + '/scans/nmap-su-' +
            self.name + '-' + str(self.ports) + 'p' + '.txt 2>/dev/null | grep -v "filtered" | nmaptocsv; ' +
            'nmap -n -T4 -Pn -sV -sS --top-ports ' + str(self.ports) + ' ' +
            str(self.ipRange[0]) +
            '/24 --max-retries 4 --host-timeout 45m  --script-timeout 45m -oN ' + self.wd + '/scans/nmap-ss-' +
            self.name + '-' + str(
                self.ports) + 'p' + '.txt 2>/dev/null | grep -v "filtered" | nmaptocsv 2>/dev/null; }').read()

        message("Nmap finished for " + self.name, event=True)
        self.enumResults = std_out


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Network reconnaissance tool to discover hosts, ports, and perform targeted recon.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--range", type=parse_range, action="store", default=False,
                       help="Enter a /24 IP range instead of predefined ranges. Separate with '-'.")
    parser.add_argument("-v", "--verbosity", action="store_true", default=False, help="Increase output verbosity.")
    group.add_argument("-c", "--cycles", action="store", default=1,
                       help="Number of scan cycles to perform. Default is 1.")
    parser.add_argument("-n", "--noscan", action="store_false", default=True,
                        help="Only performs fping and no enumeration. Does not affect --target.")
    parser.add_argument("-o", "--output", action="store", default=os.getcwd(), help="Output directory. Default is cwd.")
    parser.add_argument("-s", "--speed", action="store", type=int, choices=[1, 2, 3], default=0,
                        help="Speed options (workers) 1 (32w), 2 (50w), or 3 (68w). Default is 0 edit with caution.")
    parser.add_argument("-w", "--wait", action="store", default=60,
                        help="Number of minutes to sleep between scan cycles. Default is 60.")
    parser.add_argument("-p", "--ports", action="store", default=50,
                        help="Number of ports to set nmap top ports to. Default is 50.")
    args = parser.parse_args()

    # check for dependencies
    dep_check()

    # confirm top directory exists; if not, populate it
    wd = os.path.join(args.output, "hive-results")
    if not os.path.exists(wd):
        os.makedirs(wd, exist_ok=True)
        os.makedirs(os.path.join(wd, "target"), exist_ok=True)
        os.makedirs(os.path.join(wd, "scans"), exist_ok=True)

    # set speed
    if args.speed == 3:
        args.speed = 68
    elif args.speed == 2:
        args.speed = 50
    else:
        args.speed = 32

    # kick off
    if args.range:
        myHive = Hive(harvest=args.noscan, verbose=args.verbosity, ip_range=args.range, work_dir=wd,
                      workers=args.speed, ports=args.ports)
    else:
        myHive = Hive(harvest=args.noscan, verbose=args.verbosity, work_dir=wd, workers=args.speed, ports=args.ports)

    if args.cycles == 1:
        myHive.operate()
        myHive.report()
    else:
        cycle(myHive, args.wait, args.cycles)
