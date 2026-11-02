"""Fixed isolated import path in the reviewed image; no environment search."""
import sys
sys.path.insert(0, '/usr/lib/security-center-observation')
from boot_observer import main
main()
