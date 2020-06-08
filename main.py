import concurrent.futures
import os
from ipaddress import ip_address
from tqdm import tqdm


def gen_ip_range(start, end):
    """
    Generates IPv4 addresses inclusively
    :param start: start IPv4 address
    :param end:  end IPv4 address
    :return: list
    """
    start_int = int(ip_address(start).packed.hex(), 16)
    end_int = int(ip_address(end).packed.hex(), 16)
    return [ip_address(ip).exploded for ip in tqdm(range(start_int, end_int), desc="Generating buzz for " + str(start))]


def chunk_list(lst, n):
    """
    Splits a list into n parts
    :param lst: list obj
    :param n: parts int
    :return: list of lists
    """
    return [lst[i:i + n] for i in range(0, len(lst), n)]


class Hive:
    """
    Hive Jobs: creates the bees, operates the bees for scanning and enum, and aggregates the bees reports
    """

    def __init__(self):
        self.SubnetList = [
            ("192.168.0.0", "192.168.255.255"), ("10.0.0.0", "10.255.255.255"), ("172.16.0.0", "172.16.255.255")]
        self.Bees = []
        self._gen_bees()

    def _gen_bees(self):
        """
        Generates all the bees for the hive
        """

        for itr in self.SubnetList:
            full_ip_range = gen_ip_range(itr[0], itr[1])
            split_ip_range = chunk_list(full_ip_range, 256)

            for i in split_ip_range:
                self.Bees.append(Bee(i[0], i[-1]))

    def operate(self):
        """
        Tells bee class to scan all of the given ranges with multi-threading and found targets are harvested
        """
        print("### DEPLOYING SWARM ###")

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            list(tqdm(executor.map(Bee.is_alive, self.Bees), total=len(self.Bees), desc="Scanning"))

        live_bees = []
        for i in self.Bees:
            if i.get_status():
                live_bees.append(i)

        self.Bees = live_bees

    def report(self):
        print(len(self.Bees))
        pass


class Bee:
    """
    Bees are given an IP range to scan and then harvest IP's if their range has an alive IP address inside
    """

    def __init__(self, ip_start, ip_end):
        self.name = "Bee-" + str(ip_start) + "-" + str(ip_end)
        self.ipRange = (ip_start, ip_end)
        self.live = False

    def is_alive(self):
        """
        Tells if the Bee's assigned IP range has alive IP's inside
        """
        out = os.popen('fping -a -i 1 -r 1 -g ' + str(self.ipRange[0]) + '/24  2> /dev/null').read()

        if out == "":
            pass
        else:
            tqdm.write("A bee found some flowers in... " + str(self.ipRange[0]) + " to " + str(self.ipRange[1]))
            self.live = True
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
        pass
        # add more attacking code for sub


if __name__ == '__main__':
    myHive = Hive()
    myHive.operate()
    myHive.report()
