from .ssh import main
import sys

__all__ = ["sshcmd"]

def sshcmd():
    sys.exit(main(sys.argv))
