# Hash Hound

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Use](https://img.shields.io/badge/Use-CTF%20%7C%20Lab%20%7C%20Education-green)

Hash Hound is a lightweight command-line tool for identifying and cracking common unsalted hashes with a local wordlist. It can process a single hash or a file containing many mixed hash types, and it can also detect and decode Base64-encoded text.

> Built for cybersecurity learning, & authorized password-audit practice only.



<img width="1593" height="466" alt="image" src="https://github.com/user-attachments/assets/116adb83-462c-4b9a-8ba5-635a881c468f" />


## Features

- Identifies common hash types by digest length
- Cracks hashes using a local wordlist
- Supports single-hash mode and batch file mode
- Handles mixed hash files such as MD5, SHA1, SHA256, and SHA512 together
- Detects and decodes Base64 text
- Skips blank lines in hash files
- Shows line numbers for batch results
- Uses constant-time comparison with `hmac.compare_digest`

## Supported Hash Types

Hash Hound currently supports these algorithms through Python's `hashlib`:

- MD5
- SHA1
- SHA224
- SHA256
- SHA384
- SHA512
- SHA3-256
- SHA3-512
- BLAKE2s
- BLAKE2b

Hash identification is based on digest length, so some lengths can match more than one algorithm. In those cases, Hash Hound tries each possible candidate unless you specify an algorithm manually.

## Requirements

- Python 3.10 or newer
- A wordlist file such as `common_passwords.txt`

No third-party Python packages are required.

## Installation

Clone the repository:

```bash
git clone https://github.com/chaitanya-hack1O1/Hash-Hound-.git
cd hash-hound
```

Run the tool:

```bash
python hash_hound.py --help
```

## Usage

Identify a single hash:

```bash
python hash_hound.py HASH_HERE
```

Crack a single hash with a wordlist:

```bash
python hash_hound.py HASH_HERE -w common_passwords.txt
```

Crack a file containing one hash per line:

```bash
python hash_hound.py -f hashes.txt -w common_passwords.txt
```

Force a specific algorithm:

```bash
python hash_hound.py HASH_HERE -w common_passwords.txt -a MD5
```

Try more than one specific algorithm:

```bash
python hash_hound.py HASH_HERE -w common_passwords.txt -a SHA256 -a SHA3-256
```

Decode Base64 text:

```bash
python hash_hound.py HASH_HERE
```

## Example Batch File

Create a file named `hashes.txt`:

Add Hashes into it:

Run:

```bash
python hash_hound.py -f hashes.txt -w common_passwords.txt
```


## How It Works

Hash Hound does not reverse hashes. Hashes are one-way values. The tool cracks a hash by taking each word from your wordlist, hashing that word with the possible algorithms, and comparing the result with the target hash.

Base64 is different: it is encoding, not hashing. Base64 values can be decoded directly, so Hash Hound reports decoded Base64 text when it detects it.

## Responsible Use

Use this tool only on hashes you own, have permission to test, or are working with in a legal lab/CTF environment. Do not use it against systems, accounts, or data without authorization.

ThankYou:)

