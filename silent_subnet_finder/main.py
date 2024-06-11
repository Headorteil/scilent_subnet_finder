import multiprocessing
import os
import shlex
import shutil
import signal
import sys
from collections import Counter
from ipaddress import ip_address
from random import shuffle
from subprocess import PIPE, Popen

import pyshark
from rich.console import Console
from rich.prompt import Confirm
from rich.status import Status


class AppManager:
    def __init__(self, console, iface):
        self.console = console
        self.live = None
        self.iface = iface

        signal.signal(signal.SIGINT, self.signal_handler)

        self.q = multiprocessing.Queue()
        self.workr = multiprocessing.Process(target=self.capture)

    def run(self):
        self.workr.start()

    def signal_handler(self, *_):
        self.workr.terminate()
        list_ip = []
        while not self.q.empty():
            list_ip.append(self.q.get())

        if not list_ip:
            self.console.print("\[-] No packets were sniffed", style="red")
            return

        self.console.print()
        self.console.print("\[+] Results :", style="green")
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
            self.console.print(
                f"\[>] [bold]{i.ljust(16)}[/bold] : [bold]{j}[/bold]", style="green"
            )
        mask = max(networks, key=lambda x: networks[x])
        availible_last_byte_list = filter(
            lambda x: x not in unavailible_ips[subnet], range(2, 255)
        )
        availible_last_bytes = list(availible_last_byte_list)
        if len(availible_last_bytes) == 0:
            self.console.print(
                f"\[-] No availible ip found in subnet {subnet}/24", style="red"
            )
            return
        shuffle(availible_last_bytes)
        availible_last_byte = availible_last_bytes[0]
        ip_mask = str(ip_address(int(ip_address(mask)) + availible_last_byte)) + "/24"

        self.console.print()
        self.console.print(f"\[+] Proposition : [bold]{ip_mask}[/bold]", style="green")

        cmds = [["ip", "address", "flush", "dev", self.iface]]
        cmds.append(["ip", "address", "add", ip_mask, "dev", self.iface])
        cmds.append(["ip", "--brief", "--color", "address", "show", "dev", self.iface])
        self.console.print()
        self.execute_commands(cmds)

    def execute_commands(self, cmds):
        for cmd in cmds:
            self.console.print(f"> {shlex.join(cmd)}", style="orange1")

        self.console.print()
        execute = Confirm.ask(
            "[yellow1][?] Execute theses commands ?[yellow1]", console=self.console
        )
        if not execute:
            return
        self.console.print()
        for cmd in cmds:
            with Popen(cmd, stdout=PIPE, stderr=PIPE) as c:
                for i in [c.stdout.read(), c.stderr.read()]:
                    if i != b"":
                        self.console.print(f"> {i.decode()}", end="")

    def capture(self):
        capture = pyshark.LiveCapture(interface=self.iface, bpf_filter="ip or arp")
        with Status(
            "[blue]Gathering paquets...[/blue]",
            spinner="aesthetic",
            console=self.console,
        ) as live:
            self.live = live
            capture.apply_on_packets(self.callback)

    def callback(self, packet):
        if not ("ip" in packet or "arp" in packet):
            return
        if "ip" in packet:
            src = packet["ip"].src
            dst = packet["ip"].dst
        elif "arp" in packet:
            src = packet["arp"].dst_proto_ipv4
            dst = packet["arp"].src_proto_ipv4

        valid = False
        if valid_ip(src):
            valid = True
            self.q.put(src)
            src = f"[green]{src}[/green]"
        if valid_ip(dst):
            valid = True
            self.q.put(dst)
            dst = f"[green]{dst}[/green]"

        if valid:
            self.live.console.print(
                f"\[*] [bold]{src}[/bold] -> [bold]{dst}[/bold]", style="blue"
            )


def valid_ip(ip):
    return (
        ip_address(ip).is_private
        and not ip_address(ip).is_unspecified
        and not ip_address(ip).is_link_local
        and not ip_address(ip).is_reserved
    )


def real_main(iface):
    console = Console(highlight=False)
    if os.geteuid():
        console.print("\[*] Gaining root privileges...", style="blue")
        sudo_path = shutil.which("sudo")
        if sudo_path is None:
            console.print("\[-] Unsufficient rights and sudo not found", style="red")
            sys.exit(1)
        os.execl(sudo_path, "sudo", *sys.argv)

    console.print(
        "\[*] You should disable your network manager befure running this tool",
        style="blue",
    )

    app = AppManager(console, iface)
    app.run()
