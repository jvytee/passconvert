# PassConvert
A simple script to migrate credentials from a local [password store](https://www.passwordstore.org/) to a
[KeePass](https://keepass.info/) file.

## Installation
Clone this repository
```shell
git clone https://github.com/jvytee/passconvert.git
cd passconvert
```

and install dependencies
```shell
uv sync --locked
```

## Usage
To execute the script, source the virtualenv with dependencies first
```shell
source .venv/bin/activate
./passconvert.py
```

or run with UV: `uv run passconvert.py`.

The script works with the following arguments:
```
usage: passconvert.py [-h] [-k KEY_FILE] [-f FOLDER] [-u] password_store keepass_file

positional arguments:
  password_store        Location of password store folder
  keepass_file          Location of KeePass file

options:
  -h, --help            show this help message and exit
  -k KEY_FILE, --key-file KEY_FILE
                        Location of key file for KeePass
  -f FOLDER, --folder FOLDER
                        Password folder to import
  -u, --url-from-title  Derive URL from filename/title of password store entry
```
