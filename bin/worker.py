"""
This file is still here only to be backward compatible with the entrypoints assumed in the main repository
"""

from boefjes import __main__ as boefjes_main


if __name__ == "__main__":
    boefjes_main.cli()
