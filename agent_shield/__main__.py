"""Entry point: python3 -m agent_shield audit <directory>"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
