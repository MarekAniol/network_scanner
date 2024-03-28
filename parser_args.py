import argparse


def parse_scanner_args():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument('-ip', required=True, help="Destination IP Address")
    parser.add_argument('-f', required=True, type=str, help="Path to the file with target ports list")
    parser.add_argument('-sip', help="Spoofed Source IP Address")
    parser.add_argument('-sp', type=int, help="Spoofed Source Port")
    return parser.parse_args()