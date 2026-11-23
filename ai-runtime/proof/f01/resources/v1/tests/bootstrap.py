"""Locate the ordinary runtime sources independently of working directory."""
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
os.environ.setdefault('F01_OBSERVER_SOURCE', str(BASE / 'python/observer.py'))
os.environ.setdefault('F01_DRIVER_SOURCE', str(BASE / 'run-resources.sh'))
os.environ.setdefault('F01_CANDIDATE_SOURCE', str(BASE.parent.parent))
