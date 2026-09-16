# main.py
import argparse
import sys
from mcpguard import logger
from mcpguard.proxy import run


def main():
    parser = argparse.ArgumentParser(
        prog="mcpguard",
        description="Zero-dependency MCP security proxy",
    )
    parser.add_argument("--server", required=True, help="Command to launch the MCP server")
    parser.add_argument("--log-file", default=None, help="Path to write JSON logs (default: stderr)")
    parser.add_argument("--dry-run", action="store_true", help="Log threats but do not block")
    parser.add_argument("--allow-list", nargs="*", default=[], metavar="TOOL", help="Tool names to skip inspection")

    args = parser.parse_args()
    logger.init(args.log_file)
    run(server_cmd=args.server, dry_run=args.dry_run, allow_list=args.allow_list)


if __name__ == "__main__":
    main()