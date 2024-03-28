#!/usr/bin/python3
from scapy.all import *
from abc import ABC, abstractmethod
conf.verb = 0

#####################################
# TODO: Add MAC spoofing
#####################################

class Scanner(ABC):
    @abstractmethod
    def scan(self):
        pass

class IcmpHostScanner(Scanner):
    def __init__(self, target, src_IP=None):
        self.target = target
        self.src_IP = src_IP

    def __is_ping_reply(self, ping):
        """Checks if the ICMP response is of type 'echo reply' (numeric value 0)."""
        return ping[1][ICMP].type == 0

    def scan(self):
        print("[+] Stage: Host discovery")

        pings, unans = sr(IP(src=self.src_IP ,dst=self.target)/ICMP(), timeout=2)
        hosts = []

        for ping in pings:
            if self.__is_ping_reply(ping) == False:
                continue
            hosts.append({
                "ip": ping[0].dst,
                "services": []
            })
        return hosts

class TcpServiceScanner(Scanner):
    def __init__(self, dports, hosts, sport_TCP=None):
        self.dports = dports
        self.hosts = hosts
        self.sport_TCP = sport_TCP
    
    def __is_tcp_synack(self, packet):
        """Checks if the TCP response has the 'SA' (syn-ack) flag, indicating a successful connection establishment."""
        return packet[1][TCP].flags == "SA"

    def scan(self):
        print("[+] Stage: Service discovery")
        sport = RandShort() if self.sport_TCP is None else self.sport_TCP
        for host in self.hosts:
            tcp_results, unans = sr(IP(dst=host["ip"])/TCP(sport=sport, dport=self.dports), timeout=1)
            print(f'Host: {host["ip"]}')
            for tcp_conn in tcp_results:
                if self.__is_tcp_synack(tcp_conn) == False:
                    continue
                host["services"].append(tcp_conn[0][TCP].dport)
                print(f"\t- Open port: {tcp_conn[0][TCP].dport}")


def load_ports_from_file(filename):
    """Loads a list of ports from a file."""
    try:
        with open(filename) as f:
            ports = f.read().split(",")
        return [int(port) for port in ports]
    except FileNotFoundError:
        print("File not found.")
        sys.exit(1)
    except ValueError:
        print("Error parsing ports. Ensure the file contains only integers separated by coma.")
        sys.exit(1)

def main(args):
    target = args.ip
    ports_file = args.f
    src_IP = args.sip
    sport_TCP = args.sp

    ports = load_ports_from_file(ports_file)
    icmp_host_scanner = IcmpHostScanner(target, src_IP)
    hosts_discovered = icmp_host_scanner.scan()
    tcp_service_scanner = TcpServiceScanner(ports, hosts_discovered, sport_TCP)
    tcp_service_scanner.scan()

if __name__ == "__main__":
    import sys
    from parser_args import parse_scanner_args

    if len(sys.argv) < 3:
        print("Usage: python3 script.py <target> <ports_file> [set_source_IP] [set_sport_TCP]")
        sys.exit(1)

    args = parse_scanner_args()
    main(args)