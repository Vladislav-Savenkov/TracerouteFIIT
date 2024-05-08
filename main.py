import argparse
import re
import sys
import ipaddress
from Traceroute import Traceroute

ipv4_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
def parse_input():
    input = argparse.ArgumentParser()
    input.add_argument('ip', type=str, default='8.8.8.8')
    input.add_argument('-t', type=int, default=2)
    input.add_argument('-n', type=int, default=77)
    input.add_argument('-v', action='store_true')
    return input.parse_args()

def validate_address(address, address_type):
    try:
        address_type(address)
    except ipaddress.AddressValueError:
        print("Invalid address")
        sys.exit(-1)

def get_packet(ip, length, seq):
    if re.match(ipv4_pattern, ip):
        validate_address(ip, ipaddress.IPv4Address)
        packet_type = 'ICMPv4'
    else:
        print("Address does not match IPv4 format")
        sys.exit(-1)

    return {
        'ip': ip,
        'length': length,
        'seq': seq,
        'type': packet_type
    }

def main():
    input_args = parse_input()
    packet = get_packet(input_args.ip, 40, 0)
    tracert = Traceroute(packet, input_args.t, 0, input_args.n, input_args.v)
    tracert.execute_traceroute()

if __name__ == '__main__':
    main()