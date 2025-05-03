#! /usr/bin/env python3

import sys
from argparse import ArgumentParser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Optional

import gnupg


@dataclass
class Params:
    password_store: Path
    keepass_file: Path
    folder: Path


@dataclass
class Credentials:
    password: str = field(repr=False)
    username: Optional[str] = None
    domain: Optional[str] = None
    comment: Optional[str] = None

    @staticmethod
    def from_entry(path: Path, content: str) -> "Credentials":
        domain = f"https://{path.stem}"
        lines = content.splitlines()
        password = lines[0]

        if len(lines) <= 1:
            return Credentials(password, domain=domain)

        username = None
        comment = None
        for line in lines[1:]:
            if username is None and line.startswith("login: "):
                username = line.replace("login: ", "").strip()
                continue

            comment = line if comment is None else "\n".join((comment, line))

        if comment is not None:
            comment = comment.strip()

        return Credentials(password, username, domain, comment)


def parse_args(argv: list[str]) -> Params:
    argument_parser = ArgumentParser()
    argument_parser.add_argument(
        "password_store", type=Path, help="Location of password store folder"
    )
    argument_parser.add_argument("keepass_file", type=Path, help="Location of KeePass file")
    argument_parser.add_argument(
        "-f", "--folder", type=Path, default=Path("."), help="Password folder to import"
    )
    argument_parser.add_argument(
        "-d",
        "--domain",
        action="store_true",
        default=False,
        help="Use filename as domain for password",
    )

    args = argument_parser.parse_args(argv[1:])
    return Params(
        password_store=args.password_store, keepass_file=args.keepass_file, folder=args.folder
    )


def read_cyphertexts(
    password_store: Path, folder: Path
) -> Generator[tuple[Path, bytes], None, None]:
    folder = password_store / folder
    for filepath in folder.iterdir():
        with open(filepath, "rb") as file:
            yield filepath, file.read()


def main() -> None:
    params = parse_args(sys.argv)
    gpg = gnupg.GPG()

    for filepath, cyphertext in read_cyphertexts(params.password_store, params.folder):
        plaintext = gpg.decrypt(cyphertext)
        credentials = Credentials.from_entry(filepath, str(plaintext))
        print(credentials)


if __name__ == "__main__":
    main()
