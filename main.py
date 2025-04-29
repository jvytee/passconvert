#! /usr/bin/env python3
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from typing import Generator

import gnupg


@dataclass
class Params:
    password_store: Path
    keepass_file: Path
    folder: Path


@dataclass
class Credentials:
    password: str
    username: str
    domain: str
    comment: str


def parse_args(argv: list[str]) -> Params:
    argument_parser = ArgumentParser()
    argument_parser.add_argument("password_store", type=Path, help="Location of password store folder")
    argument_parser.add_argument("keepass_file", type=Path, help="Location of KeePass file")
    argument_parser.add_argument("-f", "--folder", type=Path, default=Path("."), help="Password folder to import")

    args = argument_parser.parse_args(argv[1:])
    return Params(
        password_store=args.password_store,
        keepass_file=args.keepass_file,
        folder=args.folder
    )


def read_cyphertexts(password_store: Path, folder: Path) -> Generator[tuple[Path, bytes], None, None]:
    folder = password_store / folder
    for filepath in folder.iterdir():
        with open(filepath, "rb") as file:
            yield filepath, file.read()


def main():
    params = parse_args(sys.argv)
    gpg = gnupg.GPG()

    for filepath, cyphertext in read_cyphertexts(params.password_store, params.folder):
        plaintext = gpg.decrypt(cyphertext)
        print(f"{filepath}: {plaintext}")


if __name__ == "__main__":
    main()
