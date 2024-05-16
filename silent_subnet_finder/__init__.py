from typing_extensions import Annotated
from enum import Enum

import psutil
import typer

from silent_subnet_finder.main import real_main

Ifaces = Enum("Ifaces", {key: key for key in psutil.net_if_addrs().keys()})

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]})


@app.command()
def main(iface: Annotated[Ifaces, typer.Argument(help="Interface to configure")]):
    """
    Update tour network config to a right one
    """
    real_main(iface.value)
