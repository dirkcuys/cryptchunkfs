# Fuse file system that store all files in encrypted chunks of a fixed size

**WARNING** This is a proof of concept and should not be considered ready for production.

## Requirements:
 - Linux
 - Python 3

## Installation & usage

1. Create a virtual env: `python3 -m venv venv`
1. Install requirements `source venv/bin/activate && pip install -r requirements.txt`
1. Run command: `python splitencfs.py`

```
usage: splitencfs.py [-h] mount store

positional arguments:
  mount
  store

optional arguments:
  -h, --help  show this help message and exit
```

You can use `mount` directory as a normal directory to copy files

Encrypted files are stored in `store`.
