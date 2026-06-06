# *Author: Avinash K*
"""Configuration loader for the Network Intrusion Detection System.
Loads settings from config.yaml.
"""
import os
import yaml

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.yaml")

def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
