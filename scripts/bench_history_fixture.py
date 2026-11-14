"""Generate a fresh synthetic 5000-commit/100-file repository for T38.

Usage on Linux: python -m scripts.bench_history_fixture /tmp/new-directory
Only a public AWS documentation example is used as a fake secret.
"""

import argparse
import os
import shutil
import subprocess  # nosec B404
from pathlib import Path

COMMITS = 5000
FILES = 100


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    destination = parser.parse_args().destination
    destination.mkdir()  # never overwrite an existing repository
    git = shutil.which("git", path=os.defpath)
    if git is None:
        raise RuntimeError("git required")
    subprocess.run([git, "-C", str(destination), "init", "-q"], check=True)  # noqa: S603  # nosec B603
    stream = bytearray()
    for number in range(COMMITS):
        stream.extend(
            f"commit refs/heads/main\nmark :{number + 1}\n"
            f"committer Synthetic <benchmark@example.invalid> {1700000000 + number} +0000\n"
            "data 9\nsynthetic\n".encode()
        )
        if number:
            stream.extend(f"from :{number}\n".encode())
        else:
            for file in range(FILES):
                data = b"print('safe')\n"
                stream.extend(f"M 100644 inline file{file}.py\ndata {len(data)}\n".encode())
                stream.extend(data + b"\n")
            data = b"AKIAIOSFODNN7EXAMPLE\n"
            stream.extend(f"M 100644 inline config.py\ndata {len(data)}\n".encode())
            stream.extend(data + b"\n")
        if number == COMMITS - 1:
            stream.extend(b"D config.py\n")
        data = f"# revision {number}\n".encode()
        stream.extend(f"M 100644 inline file0.py\ndata {len(data)}\n".encode())
        stream.extend(data + b"\n\n")
    subprocess.run(  # noqa: S603 - fixed git command, synthetic stdin  # nosec B603
        [git, "-C", str(destination), "fast-import", "--quiet"],
        input=stream,
        check=True,
    )
    subprocess.run(  # noqa: S603 - fixed git command  # nosec B603
        [git, "-C", str(destination), "symbolic-ref", "HEAD", "refs/heads/main"],
        check=True,
    )


if __name__ == "__main__":
    main()
