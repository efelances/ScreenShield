"""CLI and desktop entrypoint for ScreenShield."""

from __future__ import annotations

import argparse

from screenshield import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="screenshield", description="ScreenShield")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument("--headless", action="store_true", help="Run localhost server without pywebview")
    parser.add_argument("--port", type=int, default=0, help="Localhost port (default: ephemeral)")
    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    from screenshield.desktop import run_desktop, run_headless

    if args.headless:
        return run_headless(port=args.port or 8765)
    return run_desktop(port=args.port)


if __name__ == "__main__":
    raise SystemExit(main())
