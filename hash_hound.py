#!/usr/bin/env python3
"""Identify and crack common unsalted hashes for CTF/lab use."""

import argparse
import base64
import binascii
import hashlib
import hmac
import sys
from pathlib import Path


HASH_SIGNATURES = {
    32: ("MD5",),
    40: ("SHA1",),
    56: ("SHA224",),
    64: ("SHA256", "SHA3-256", "BLAKE2s"),
    96: ("SHA384",),
    128: ("SHA512", "SHA3-512", "BLAKE2b"),
}

HASHLIB_NAMES = {
    "MD5": "md5",
    "SHA1": "sha1",
    "SHA224": "sha224",
    "SHA256": "sha256",
    "SHA384": "sha384",
    "SHA512": "sha512",
    "SHA3-256": "sha3_256",
    "SHA3-512": "sha3_512",
    "BLAKE2s": "blake2s",
    "BLAKE2b": "blake2b",
}

BANNER = r"""
 _   _           _       _   _                       _
| | | | __ _ ___| |__   | | | | ___  _   _ _ __   __| |
| |_| |/ _` / __| '_ \  | |_| |/ _ \| | | | '_ \ / _` |
|  _  | (_| \__ \ | | | |  _  | (_) | |_| | | | | (_| |
|_| |_|\__,_|___/_| |_| |_| |_|\___/ \__,_|_| |_|\__,_|
Common Hash Cracking Tool By Mainekhacker
"""


def resolve_wordlist_path(wordlist_path: str | Path) -> Path:
    """Find a wordlist from the current folder or beside this script."""
    raw_path = Path(wordlist_path).expanduser()
    candidates = [raw_path]

    if not raw_path.is_absolute():
        script_dir = Path(__file__).resolve().parent
        candidates.append(script_dir / raw_path)
        if len(raw_path.parts) > 1 and raw_path.parts[0] == script_dir.name:
            candidates.append(script_dir / Path(*raw_path.parts[1:]))

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(f"wordlist not found: {wordlist_path}")


def normalize_hash(hash_value: str) -> str:
    """Return a lowercase hex digest or raise ValueError."""
    cleaned = hash_value.strip().lower()
    if not cleaned:
        raise ValueError("hash value cannot be empty")
    if not all(character in "0123456789abcdef" for character in cleaned):
        raise ValueError("hash value must be hexadecimal")
    return cleaned


def identify_hash(hash_value: str) -> list[str]:
    """Guess possible hash algorithms from digest length and characters."""
    digest = normalize_hash(hash_value)
    return list(HASH_SIGNATURES.get(len(digest), ()))


def decode_base64(value: str) -> str | None:
    """Return decoded Base64 text, or None when the value is not Base64 text."""
    cleaned = value.strip()
    if len(cleaned) < 4:
        return None

    padding_needed = -len(cleaned) % 4
    padded = cleaned + ("=" * padding_needed)

    try:
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded_text = decoded_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None

    if not decoded_text or not all(character.isprintable() for character in decoded_text):
        return None

    return decoded_text


def print_base64_decoding(value: str) -> bool:
    """Print a Base64 decode result when available."""
    decoded_text = decode_base64(value)
    if decoded_text is None:
        return False

    print(f"Decoded Base64: {decoded_text}")
    return True


def hash_text(text: str, algorithm: str) -> str:
    """Hash text with a supported hashlib algorithm."""
    algorithm_name = HASHLIB_NAMES.get(algorithm.upper(), algorithm.lower())
    try:
        hasher = hashlib.new(algorithm_name)
    except ValueError as exc:
        raise ValueError(f"unsupported hash algorithm: {algorithm}") from exc

    hasher.update(text.encode("utf-8"))
    return hasher.hexdigest()


def crack_with_wordlist(
    hash_value: str,
    wordlist_path: str | Path,
    algorithms: list[str] | None = None,
) -> tuple[str, str] | None:
    """Try each word in a wordlist against the target digest."""
    target = normalize_hash(hash_value)
    path = resolve_wordlist_path(wordlist_path)

    candidates = algorithms or identify_hash(target)
    if not candidates:
        raise ValueError("unknown hash type; pass an algorithm explicitly")

    with path.open("r", encoding="utf-8", errors="ignore") as wordlist:
        for raw_word in wordlist:
            word = raw_word.rstrip("\r\n")
            for algorithm in candidates:
                if hmac.compare_digest(hash_text(word, algorithm), target):
                    return word, algorithm

    return None


def read_hash_file(hash_file_path: str | Path) -> list[tuple[int, str]]:
    """Read non-empty hashes from a file with their original line numbers."""
    path = Path(hash_file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"hash file not found: {hash_file_path}")

    hashes = []
    with path.open("r", encoding="utf-8", errors="ignore") as hash_file:
        for line_number, raw_line in enumerate(hash_file, start=1):
            hash_value = raw_line.strip()
            if hash_value:
                hashes.append((line_number, hash_value))

    if not hashes:
        raise ValueError("hash file does not contain any hashes")

    return hashes


def crack_hash_file(
    hash_file_path: str | Path,
    wordlist_path: str | Path,
    algorithms: list[str] | None = None,
) -> None:
    """Crack every hash in a file and print one result per line."""
    hashes = read_hash_file(hash_file_path)

    for line_number, hash_value in hashes:
        try:
            possible_types = identify_hash(hash_value)
            type_label = ", ".join(possible_types) if possible_types else "unknown"
            result = crack_with_wordlist(hash_value, wordlist_path, algorithms)
        except ValueError as exc:
            decoded_text = decode_base64(hash_value)
            if decoded_text is not None:
                print(
                    f"Line {line_number}: {hash_value} -> "
                    f"Decoded Base64: {decoded_text}"
                )
                continue

            print(f"Line {line_number}: {hash_value} -> Error: {exc}")
            continue

        if result:
            plaintext, algorithm = result
            print(
                f"Line {line_number}: {hash_value} -> Found: "
                f"{plaintext} ({algorithm})"
            )
        else:
            print(
                f"Line {line_number}: {hash_value} -> "
                f"Not found ({type_label})"
            )


def print_identification(hash_value: str) -> None:
    try:
        possible_types = identify_hash(hash_value)
    except ValueError:
        if print_base64_decoding(hash_value):
            return
        raise

    if possible_types:
        print("Possible hash type(s): " + ", ".join(possible_types))
    else:
        print("Could not identify this hash by length.")


def print_banner() -> None:
    print(BANNER)


def print_crack_result(result: tuple[str, str] | None) -> None:
    if result:
        plaintext, algorithm = result
        print(f"Found: {plaintext} ({algorithm})")
    else:
        print("Password not found in wordlist.")


def interactive_crack() -> None:
    print_banner()
    hash_value = input("Enter hash: ").strip()
    try:
        print_identification(hash_value)
    except ValueError as exc:
        print(f"Error: {exc}")
        return

    wordlist = input("Wordlist path: ").strip()
    try:
        result = crack_with_wordlist(hash_value, wordlist)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}")
        return

    print_crack_result(result)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Identify and crack common unsalted hashes."
    )
    parser.add_argument("hash", nargs="?", help="hash digest to inspect")
    parser.add_argument(
        "-f",
        "--file",
        help="file containing one hash per line",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        help="wordlist file to use for local cracking",
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        action="append",
        choices=sorted(HASHLIB_NAMES),
        help="algorithm to try; can be used more than once",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.hash and args.file:
        parser.error("use either a single hash or --file, not both")

    if args.file and not args.wordlist:
        parser.error("--file requires --wordlist")

    if not args.hash:
        if args.file:
            try:
                print_banner()
                crack_hash_file(args.file, args.wordlist, args.algorithm)
            except (FileNotFoundError, ValueError) as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 1
            return 0

        interactive_crack()
        return 0

    try:
        print_banner()
        print_identification(args.hash)
        try:
            normalize_hash(args.hash)
        except ValueError:
            return 0

        if args.wordlist:
            result = crack_with_wordlist(args.hash, args.wordlist, args.algorithm)
            print_crack_result(result)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
