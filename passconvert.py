#! /usr/bin/env python3

import logging
import sys
from argparse import ArgumentParser
from dataclasses import dataclass, field
from getpass import getpass
from pathlib import Path
from typing import Generator, Optional

import gnupg
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError


logging.basicConfig(format="{asctime} {levelname}: {message}", style="{", level=logging.INFO)
LOGGER = logging.getLogger(__name__)


@dataclass
class Params:
    password_store: Path
    keepass_file: Path
    folder: Path
    key_file: Optional[Path] = None
    url_from_title: bool = False
    verbose: bool = False


@dataclass
class Credentials:
    title: str
    password: str = field(repr=False)
    username: Optional[str] = None
    url: Optional[str] = None
    comment: Optional[str] = None

    @staticmethod
    def from_entry(path: Path, content: str, url_from_title: bool = False) -> "Credentials":
        title = path.stem
        domain = f"https://{title}" if url_from_title else None
        lines = content.splitlines()
        password = lines[0]

        if len(lines) <= 1:
            return Credentials(title, password, url=domain)

        username = None
        comment = None
        for line in lines[1:]:
            if username is None and line.startswith("login: "):
                username = line.replace("login: ", "").strip()
                continue

            comment = line if comment is None else "\n".join((comment, line))

        if comment is not None:
            comment = comment.strip()

        return Credentials(title, password, username, domain, comment)

    def save(self, keepass: PyKeePass, folder: str) -> None:
        if (group := keepass.find_groups(name=folder, first=True)) is None:
            group = keepass.add_group(keepass.root_group, folder)

        username = self.username or ""
        keepass.add_entry(group, self.title, username, self.password, self.url, self.comment)


def parse_args(argv: list[str]) -> Params:
    argument_parser = ArgumentParser()
    argument_parser.add_argument(
        "password_store", type=Path, help="Location of password store folder"
    )
    argument_parser.add_argument("keepass_file", type=Path, help="Location of KeePass file")
    argument_parser.add_argument(
        "-k", "--key-file", type=Path, default=None, help="Location of key file for KeePass"
    )
    argument_parser.add_argument(
        "-f", "--folder", type=Path, default=Path("."), help="Password folder to import"
    )
    argument_parser.add_argument(
        "-u",
        "--url-from-title",
        action="store_true",
        default=False,
        help="Derive URL from filename/title of password store entry",
    )
    argument_parser.add_argument(
        "-v", "--verbose", action="store_true", default=False, help="Increase output verbosity"
    )

    args = argument_parser.parse_args(argv[1:])
    return Params(
        password_store=args.password_store,
        keepass_file=args.keepass_file,
        folder=args.folder,
        key_file=args.key_file,
        url_from_title=args.url_from_title,
        verbose=args.verbose,
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

    LOGGER.info("Initializing GPG")
    gpg = gnupg.GPG()

    LOGGER.info("Loading KeePass file %s", params.keepass_file)
    password = getpass(f"Password for {params.keepass_file}: ")
    try:
        keepass = PyKeePass(params.keepass_file, password=password, keyfile=params.key_file)
    except CredentialsError:
        LOGGER.error("Could not open %s due to invalid credentials", params.keepass_file)
        return

    LOGGER.info("Converting passwords in %s", params.password_store / params.folder)
    for filepath, cyphertext in read_cyphertexts(params.password_store, params.folder):
        plaintext = gpg.decrypt(cyphertext)
        credentials = Credentials.from_entry(filepath, str(plaintext), params.url_from_title)

        try:
            credentials.save(keepass, str(params.folder))
        except Exception as e:
            LOGGER.warning("Could not save credentials for %s: %s", credentials.title, e)

        if params.verbose:
            LOGGER.info("%s", credentials)
        else:
            print(".", end="", flush=True)

    # Produce a newline
    print()

    LOGGER.info("Saving KeePass file %s", params.keepass_file)
    keepass.save()

    LOGGER.info("Done.")


if __name__ == "__main__":
    main()
