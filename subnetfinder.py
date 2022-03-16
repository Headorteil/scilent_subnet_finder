#! /usr/bin/env python3

import pyshark
import os
import argparse
import signal
import sys
import shutil

import multiprocessing
from subprocess import Popen, PIPE
from random import shuffle
from ipaddress import ip_address
from collections import Counter

# https://docs.python.org/3/library/ipaddress.html


def valid_ip(ip):
    return (
        ip_address(ip).is_private
        and not ip_address(ip).is_unspecified
        and not ip_address(ip).is_link_local
        and not ip_address(ip).is_reserved
    )


def green(msg):
    return "\033[92m{}\033[00m".format(msg)


def callback(packet):
    test = False
    if "ip" in packet:
        src = packet["ip"].src
        dst = packet["ip"].dst
        if valid_ip(src):
            test = True
            q.put(src)
            src = green(src)
        if valid_ip(dst):
            test = True
            q.put(dst)
            dst = green(dst)
        if test:
            res = "[*] {} -> {}".format(src, dst)
            print(res)
    elif "arp" in packet:
        src = packet["arp"].dst_proto_ipv4
        dst = packet["arp"].src_proto_ipv4
        if valid_ip(src):
            test = True
            q.put(src)
            src = green(src)
        if valid_ip(dst):
            test = True
            q.put(dst)
            dst = green(dst)
        if test:
            res = "[*] {} -> {}".format(src, dst)
            print(res)


def signal_handler(sig, frame):
    workr.terminate()
    list_ip = []
    while not q.empty():
        list_ip.append(q.get())

    if not list_ip:
        print("\n[-] No packets were sniffed")
        return

    print("\n[+] Results :")
    ip_ctr = Counter(list_ip).most_common()
    unavailible_ips = {}
    networks = {}
    for i, j in ip_ctr:
        subnet = str(ip_address(int(ip_address(i)) & ~0xFF))
        last_byte = int(ip_address(i)) & 0xFF
        if subnet in networks:
            networks[subnet] += j
            unavailible_ips[subnet].append(last_byte)
        else:
            networks[subnet] = j
            unavailible_ips[subnet] = [last_byte]
        print("[>] {} : {}".format(green(i.ljust(16)), j))
    mask = max(networks, key=lambda x: networks[x])
    availible_last_byte_list = filter(
        lambda x: x not in unavailible_ips[subnet], range(2, 255)
    )
    availible_last_bytes = list(availible_last_byte_list)
    if len(availible_last_bytes) == 0:
        print("Error, no availible ip found in subnet {}/24".format(subnet))
        return
    else:
        shuffle(availible_last_bytes)
        availible_last_byte = availible_last_bytes[0]
    ip_mask = str(ip_address(int(ip_address(mask)) + availible_last_byte)) + "/24"

    print("\n[+] Proposition : {}".format(green(ip_mask)))

    cmd1 = ["ip", "address", "flush", "dev", iface]
    cmd2 = ["ip", "address", "add", ip_mask, "dev", iface]
    cmd3 = ["ip", "--brief", "address", "show", "dev", iface]
    while True:
        print()
        print("> " + " ".join(cmd1))
        print("> " + " ".join(cmd2))
        print("> " + " ".join(cmd3))
        print()
        print("[?] Execute theses commands ? [Y]n")
        resp = input(">>> ")
        if resp.lower() == "n":
            exit(0)
        elif resp == "" or resp.lower() == "y":
            break
    with Popen(cmd1, stdout=PIPE, stderr=PIPE) as a:
        [
            print("> " + i.decode(), end="")
            for i in [a.stdout.read(), a.stderr.read()]
            if i != b""
        ]
    with Popen(cmd2, stdout=PIPE, stderr=PIPE) as a:
        [
            print("> " + i.decode(), end="")
            for i in [a.stdout.read(), a.stderr.read()]
            if i != b""
        ]
    with Popen(cmd3, stdout=PIPE, stderr=PIPE) as a:
        [
            print("> " + i.decode(), end="")
            for i in [a.stdout.read(), a.stderr.read()]
            if i != b""
        ]


def run(q):
    capture = pyshark.LiveCapture(interface=iface, bpf_filter="ip or arp")
    capture.apply_on_packets(callback)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Auto subnet configuration")
    parser.add_argument("-I", dest="iface", type=str, required=True)
    args = parser.parse_args()

    if os.geteuid():
        print("[*] Gaining root privileges...")
        sudo_path = shutil.which("sudo")
        if sudo_path is None:
            print("[-] Unsufficient rights and sudo not found")
            sys.exit(1)
        os.execl(sudo_path, sudo_path, sys.executable, __file__, *sys.argv[1:])

    cmd = ["systemctl", "stop", "NetworkManager.service"]
    while True:
        print()
        print("> " + " ".join(cmd))
        print()
        print("[?] Execute this command ? [Y]n")
        resp = input(">>> ")
        if resp == "" or resp.lower() == "y":
            with Popen(cmd, stdout=PIPE, stderr=PIPE) as a:
                [
                    print("> " + i.decode(), end="")
                    for i in [a.stdout.read(), a.stderr.read()]
                    if i != b""
                ]
            break
        elif resp.lower() == "n":
            break
    print()

    iface = args.iface

    signal.signal(signal.SIGINT, signal_handler)

    q = multiprocessing.Queue()
    list_ip = []
    workr = multiprocessing.Process(target=run, args=(q,))
    workr.start()
