from enum import Enum

from typing import Union


class Chain(Enum):
    MAIN = 0
    TEST = 1
    REGTEST = 2
    SIGNET = 3

    def __str__(self) -> str:
        return self.name.lower()

    def __repr__(self) -> str:
        return str(self)

    @staticmethod
    def argparse(s: str) -> Union['Chain', str]:
        try:
            return Chain[s.upper()]
        except KeyError:
            return s
