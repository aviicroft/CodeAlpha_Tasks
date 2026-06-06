# *Author: Avinash K*
"""Run the NIDS detector for a short trial.
It starts packet sniffing in a background thread, sleeps for 12 seconds,
then exits. All alerts are logged to logs/alerts.csv.
"""
import time
from nids.detector import start_sniff

if __name__ == "__main__":
    # Start sniffing (default interface)
    start_sniff()
    # Run for 12 seconds to allow simulated traffic to be captured
    time.sleep(12)
