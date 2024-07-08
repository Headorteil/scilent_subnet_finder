"""Main lib of silent-subnet-finder."""

from __future__ import annotations

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
from typing import TYPE_CHECKING, Any

import pyshark
from rich.console import Console
from rich.prompt import Confirm
from rich.status import Status

if TYPE_CHECKING:
    from pyshark.packet.packet import Packet


class AppManager:
    """Main class which handles the whole process."""

    def __init__(self: AppManager, console: Console, iface: str) -> None:
        """Initialize AppManager."""
        self.__console = console
        self.__live = None
        self.__iface = iface

        signal.signal(signal.SIGINT, self.__signal_handler)

        self.__queue = multiprocessing.Queue()
        self.__worker = multiprocessing.Process(target=self.__capture)

    def run(self: AppManager) -> None:
        """Start to listen to the network."""
        self.__worker.start()

    def __signal_handler(self: AppManager, *_: Any) -> None:  # noqa: ANN401
        self.__worker.terminate()
        list_ip = []
        while not self.__queue.empty():
            list_ip.append(self.__queue.get())

        if not list_ip:
            self.__console.print()
            self.__console.print(r"\[-] No packets were sniffed", style="red")
            return

        self.__console.print()
        self.__console.print(r"\[+] Results :", style="green")
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
            self.__console.print(
                rf"\[>] [bold]{i.ljust(16)}[/bold] : [bold]{j}[/bold]",
                style="green",
            )
        mask = max(networks, key=lambda x: networks[x])
        availible_last_byte_list = filter(
            lambda x: x not in unavailible_ips[subnet],
            range(2, 255),
        )
        availible_last_bytes = list(availible_last_byte_list)
        if len(availible_last_bytes) == 0:
            self.__console.print(
                rf"\[-] No availible ip found in subnet {subnet}/24",
                style="red",
            )
            return
        shuffle(availible_last_bytes)
        availible_last_byte = availible_last_bytes[0]
        ip_mask = str(ip_address(int(ip_address(mask)) + availible_last_byte)) + "/24"

        self.__console.print()
        self.__console.print(
            rf"\[+] Proposition : [bold]{ip_mask}[/bold]", style="green"
        )

        cmds = [["ip", "address", "flush", "dev", self.__iface]]
        cmds.append(["ip", "address", "add", ip_mask, "dev", self.__iface])
        cmds.append(
            ["ip", "--brief", "--color", "address", "show", "dev", self.__iface]
        )
        self.__console.print()
        self.__execute_commands(cmds)

    def __execute_commands(self: AppManager, cmds: list[str]) -> None:
        for cmd in cmds:
            self.__console.print(f"> {shlex.join(cmd)}", style="orange1")

        self.__console.print()
        execute = Confirm.ask(
            "[yellow1][?] Execute theses commands ?[yellow1]",
            console=self.__console,
        )
        if not execute:
            return
        self.__console.print()
        for cmd in cmds:
            with Popen(cmd, stdout=PIPE, stderr=PIPE) as c:  # noqa: S603
                for i in [c.stdout.read(), c.stderr.read()]:
                    if i != b"":
                        self.__console.print(f"> {i.decode()}", end="")

    def __capture(self: AppManager) -> None:
        capture = pyshark.LiveCapture(interface=self.__iface, bpf_filter="ip or arp")
        with Status(
            "[blue]Gathering paquets...[/blue]",
            spinner="aesthetic",
            console=self.__console,
        ) as live:
            self.__live = live
            capture.apply_on_packets(self.__callback)

    def __callback(self: AppManager, packet: Packet) -> None:
        if not ("ip" in packet or "arp" in packet):
            return
        if "ip" in packet:
            src = packet["ip"].src
            dst = packet["ip"].dst
        elif "arp" in packet:
            src = packet["arp"].dst_proto_ipv4
            dst = packet["arp"].src_proto_ipv4

        valid = False
        if self.__valid_ip(src):
            valid = True
            self.__queue.put(src)
            src = f"[green]{src}[/green]"
        if self.__valid_ip(dst):
            valid = True
            self.__queue.put(dst)
            dst = f"[green]{dst}[/green]"

        if valid:
            self.__live.console.print(
                rf"\[*] [bold]{src}[/bold] -> [bold]{dst}[/bold]",
                style="blue",
            )

    @staticmethod
    def __valid_ip(ip: str) -> bool:
        """Check if the input IP is interesting in a private network."""
        return (
            ip_address(ip).is_private
            and not ip_address(ip).is_unspecified
            and not ip_address(ip).is_link_local
            and not ip_address(ip).is_reserved
        )


def real_main(iface: str) -> None:
    """Real main to be able to use the package without the CLI."""
    console = Console(highlight=False)
    if os.geteuid():
        console.print(r"\[*] Gaining root privileges...", style="blue")
        sudo_path = shutil.which("sudo")
        if sudo_path is None:
            console.print(r"\[-] Unsufficient rights and sudo not found", style="red")
            sys.exit(1)
        os.execl(sudo_path, "sudo", *sys.argv)  # noqa: S606

    console.print(
        r"\[*] You should disable your network manager befure running this tool",
        style="blue",
    )

    app = AppManager(console, iface)
    app.run()
