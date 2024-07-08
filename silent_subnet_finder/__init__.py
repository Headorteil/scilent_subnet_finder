"""Listen to the network and get a proper IP."""

from enum import Enum

import psutil
import typer
from typing_extensions import Annotated

from silent_subnet_finder.main import real_main

Ifaces = Enum("Ifaces", {key: key for key in psutil.net_if_addrs()})

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]})


@app.command()
def main(
    iface: Annotated[Ifaces, typer.Argument(help="Interface to configure")],
) -> None:
    """Update tour network config to a right one."""
    real_main(iface.value)
