import asyncio
import concurrent.futures
import os
import time
from ipaddress import ip_address


# needs argv
# should this be in /16 rather than /24
# is nmaptocsv the best way to agg results?


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
        print(f'{bcolors.FAIL}{bcolors.UNDERLINE}[ ! ] [{tm}] {msg}{bcolors.ENDC}')
    elif event:
        print(f'{bcolors.OKGREEN}[ + ] [{tm}] {msg}{bcolors.ENDC}')
    else:
        print(f'{bcolors.OKCYAN}[ - ] [{tm}] {msg}{bcolors.ENDC}')


class Hive:
    """
    Hive Jobs: creates the bees, operates the bees for scanning and enum, and aggregates the bees reports
    """

    def __init__(self, harvest=False, verbose=True):
        self.SubnetList = [
            ("192.168.0.0", "192.168.255.255")]  # , ("10.0.0.0", "10.255.255.255"), ("172.16.0.0", "172.16.255.255")]
        self.Bees = []
        asyncio.run(self._gen_bees(harvest, verbose))

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
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(Bee.is_alive, self.Bees)

        live_bees = []
        for i in self.Bees:
            if i.get_status():
                live_bees.append(i)

        self.Bees = live_bees

    def report(self):
        printer("Hive Completed. Number of successful bees: " + str(len(self.Bees)), event=True)
        for i in self.Bees:
            printer(str(i._get_range()[0]) + "/24", event=True)


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

    def get_status(self):
        """
        Bee reports if its range is alive
        :return: bool
        """
        return self.live

    def _get_range(self):
        """
        Bee reports its assigned IP range
        :return: tuple
        """
        return self.ipRange

    def _harvest(self):
        printer("Starting Nmap for " + self.name, event=True)
        out = os.popen('nmap -n -Pn -p 80,443,22,21,23 ' + str(self.ipRange[0]) + "-255 2>/dev/null | nmaptocsv").read()
        printer("Nmap finished for " + self.name, event=True)


if __name__ == '__main__':
    myHive = Hive(harvest=False, verbose=True)
    myHive.operate()
    myHive.report()
