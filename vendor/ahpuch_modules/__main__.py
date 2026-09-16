"""Compatibility alias for ``python -m ahpuch_modules``."""
from ahpuch_modules.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
