from .crypto import CryptoPlugin
from .files import FilePlugin
from .reversing import ReversingPlugin
from .web import WebPlugin
from .forensics import ForensicsPlugin
from .pwn import PwnPlugin

ALL_PLUGINS = [
    FilePlugin(),
    CryptoPlugin(),
    ReversingPlugin(),
    WebPlugin(),
    ForensicsPlugin(),
    PwnPlugin(),
]
