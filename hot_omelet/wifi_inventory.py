#!/usr/bin/env python3
"""
WiFi Client Inventory Scanner - Extract all laptop/mobile devices from Cisco WLC via SNMP.

Usage:
    python3 hot_omelet/wifi_inventory.py --wlc 10.22.64.6
    python3 hot_omelet/wifi_inventory.py --wlc 10.22.64.6 --community private --output reports/wifi-network/loot
    python3 hot_omelet/wifi_inventory.py --wlc 10.22.64.6 --format json
    python3 hot_omelet/wifi_inventory.py --wlc 10.22.64.6 --filter staff
    python3 hot_omelet/wifi_inventory.py --wlc 10.22.64.6 --filter laptop --vendor-lookup
"""

import subprocess
import re
import json
import csv
import sys
import os
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime

# --- MAC OUI Database (top vendors, expandable) ---
OUI_DB = {
    # Intel WiFi (Laptops)
    "00:1b:21": "Intel", "00:1c:bf": "Intel", "00:1d:e0": "Intel",
    "00:1e:64": "Intel", "00:1e:65": "Intel", "00:21:5c": "Intel",
    "00:21:6a": "Intel", "00:24:d6": "Intel", "00:24:d7": "Intel",
    "04:ea:56": "Intel", "04:ec:d8": "Intel", "08:9d:f4": "Intel",
    "08:d4:0c": "Intel", "10:91:d1": "Intel", "14:75:5b": "Intel",
    "18:56:80": "Intel", "1c:1b:b5": "Intel", "24:4b:fe": "Intel",
    "28:c5:d2": "Intel", "28:d0:ea": "Intel", "2c:33:58": "Intel",
    "2c:6d:c1": "Intel", "30:f6:ef": "Intel", "34:13:e8": "Intel",
    "3c:21:9c": "Intel", "3c:58:c2": "Intel", "40:74:e0": "Intel",
    "44:85:00": "Intel", "48:a4:72": "Intel", "4c:03:4f": "Intel",
    "4c:34:88": "Intel", "54:6c:eb": "Intel", "58:6c:25": "Intel",
    "5c:87:9c": "Intel", "60:45:2e": "Intel", "60:6c:66": "Intel",
    "6c:2f:80": "Intel", "6c:f6:da": "Intel", "70:a6:cc": "Intel",
    "70:a8:d3": "Intel", "74:04:f1": "Intel", "74:e5:f9": "Intel",
    "7c:21:4a": "Intel", "7c:50:79": "Intel", "7c:70:db": "Intel",
    "80:86:f2": "Intel", "84:7b:57": "Intel", "8c:17:59": "Intel",
    "90:61:ae": "Intel", "98:59:7a": "Intel", "a0:80:69": "Intel",
    "a0:d3:65": "Intel", "ac:74:b1": "Intel", "b0:3c:dc": "Intel",
    "b4:69:21": "Intel", "bc:03:58": "Intel", "bc:09:1b": "Intel",
    "c8:ff:28": "Intel", "cc:15:31": "Intel", "d0:3c:1f": "Intel",
    "d4:d8:53": "Intel", "d4:e9:8a": "Intel", "d4:f3:2d": "Intel",
    "dc:1b:a1": "Intel", "dc:97:ba": "Intel", "e0:d4:e8": "Intel",
    "e4:0d:36": "Intel", "e4:c7:67": "Intel", "e8:b0:c5": "Intel",
    "e8:bf:b8": "Intel", "ec:63:d7": "Intel", "f0:9e:4a": "Intel",
    "f4:26:79": "Intel", "f4:3b:d8": "Intel", "f4:6d:3f": "Intel",
    "f4:7b:09": "Intel",
    # Liteon (Laptop WiFi cards - ASUS, Acer, Dell, HP)
    "c0:35:32": "Liteon", "b8:1e:a4": "Liteon", "e0:0a:f6": "Liteon",
    "70:08:94": "Liteon", "d0:39:57": "Liteon", "24:b2:b9": "Liteon",
    "9c:2f:9d": "Liteon", "f4:6a:dd": "Liteon", "14:5a:fc": "Liteon",
    # AzureWave (Laptop WiFi cards - ASUS, Lenovo, HP)
    "cc:47:40": "AzureWave", "14:13:33": "AzureWave", "f8:3d:c6": "AzureWave",
    "34:6f:24": "AzureWave", "a8:41:f4": "AzureWave", "b4:8c:9d": "AzureWave",
    "f8:54:f6": "AzureWave", "90:e8:68": "AzureWave", "2c:3b:70": "AzureWave",
    "28:d0:43": "AzureWave", "50:bb:b5": "AzureWave", "20:0b:74": "AzureWave",
    "10:68:38": "AzureWave", "9c:c7:d3": "AzureWave", "1c:ce:51": "AzureWave",
    "ec:2e:98": "AzureWave", "50:5a:65": "AzureWave",
    # Apple (MacBook / iPhone / iPad)
    "00:03:93": "Apple", "00:0a:27": "Apple", "00:0a:95": "Apple",
    "00:0d:93": "Apple", "00:10:fa": "Apple", "00:11:24": "Apple",
    "00:14:51": "Apple", "00:16:cb": "Apple", "00:17:f2": "Apple",
    "00:19:e3": "Apple", "00:1b:63": "Apple", "00:1c:b3": "Apple",
    "00:1d:4f": "Apple", "00:1e:52": "Apple", "00:1e:c2": "Apple",
    "00:1f:5b": "Apple", "00:1f:f3": "Apple", "00:21:e9": "Apple",
    "00:22:41": "Apple", "00:23:12": "Apple", "00:23:32": "Apple",
    "00:23:6c": "Apple", "00:23:df": "Apple", "00:24:36": "Apple",
    "00:25:00": "Apple", "00:25:4b": "Apple", "00:25:bc": "Apple",
    "00:26:08": "Apple", "00:26:4a": "Apple", "00:26:b0": "Apple",
    "00:26:bb": "Apple", "04:0c:ce": "Apple", "04:15:52": "Apple",
    "04:26:65": "Apple", "04:48:9a": "Apple", "04:52:f3": "Apple",
    "04:54:53": "Apple", "04:db:56": "Apple", "04:e5:36": "Apple",
    "04:f1:3e": "Apple", "04:f7:e4": "Apple", "08:66:98": "Apple",
    "08:6d:41": "Apple", "0c:4d:e9": "Apple", "0c:74:c2": "Apple",
    "10:40:f3": "Apple", "10:94:bb": "Apple", "10:dd:b1": "Apple",
    "14:10:9f": "Apple", "14:7f:ce": "Apple", "14:99:e2": "Apple",
    "14:bd:61": "Apple", "18:20:32": "Apple", "18:34:51": "Apple",
    "18:65:90": "Apple", "18:9e:fc": "Apple", "18:af:61": "Apple",
    "18:e7:f4": "Apple", "1c:36:bb": "Apple", "1c:57:dc": "Apple",
    "1c:91:48": "Apple", "1c:ab:a7": "Apple", "20:3c:ae": "Apple",
    "20:78:f0": "Apple", "20:9b:cd": "Apple", "20:a2:e4": "Apple",
    "20:ab:37": "Apple", "24:24:0e": "Apple", "24:a0:74": "Apple",
    "24:a2:e1": "Apple", "24:f0:94": "Apple", "28:0b:5c": "Apple",
    "28:37:37": "Apple", "28:6a:ba": "Apple", "28:a0:2b": "Apple",
    "28:cf:e9": "Apple", "28:e1:4c": "Apple", "28:e7:cf": "Apple",
    "28:ed:6a": "Apple", "2c:b4:3a": "Apple", "2c:be:08": "Apple",
    "2c:f0:ee": "Apple", "30:10:e4": "Apple", "30:35:ad": "Apple",
    "30:63:6b": "Apple", "30:90:ab": "Apple", "30:f7:72": "Apple",
    "34:08:bc": "Apple", "34:12:98": "Apple", "34:36:3b": "Apple",
    "34:51:c9": "Apple", "34:ab:37": "Apple", "34:c0:59": "Apple",
    "34:e2:fd": "Apple", "38:0f:4a": "Apple", "38:48:4c": "Apple",
    "38:53:9c": "Apple", "38:66:f0": "Apple", "38:71:de": "Apple",
    "38:b5:4d": "Apple", "38:c9:86": "Apple", "3c:07:54": "Apple",
    "3c:15:c2": "Apple", "3c:2e:f9": "Apple", "40:30:04": "Apple",
    "40:33:1a": "Apple", "40:4d:7f": "Apple", "40:6c:8f": "Apple",
    "40:98:ad": "Apple", "40:a6:d9": "Apple", "40:b3:95": "Apple",
    "40:cb:c0": "Apple", "40:d3:2d": "Apple", "44:00:10": "Apple",
    "44:2a:60": "Apple", "44:d8:84": "Apple", "44:fb:42": "Apple",
    "48:43:7c": "Apple", "48:74:6e": "Apple", "48:a1:95": "Apple",
    "48:bf:6b": "Apple", "48:d7:05": "Apple", "48:e9:f1": "Apple",
    "4c:32:75": "Apple", "4c:56:9d": "Apple", "4c:57:ca": "Apple",
    "4c:74:03": "Apple", "4c:8d:79": "Apple", "4c:b1:99": "Apple",
    "50:32:37": "Apple", "50:7a:55": "Apple", "50:82:d5": "Apple",
    "50:bc:96": "Apple", "50:ea:d6": "Apple", "54:26:96": "Apple",
    "54:4e:90": "Apple", "54:72:4f": "Apple", "54:99:63": "Apple",
    "54:ae:27": "Apple", "54:e4:3a": "Apple", "54:ea:a8": "Apple",
    "58:1f:aa": "Apple", "58:40:4e": "Apple", "58:55:ca": "Apple",
    "58:b0:35": "Apple", "5c:59:48": "Apple", "5c:8d:4e": "Apple",
    "5c:95:ae": "Apple", "5c:96:9d": "Apple", "5c:97:f3": "Apple",
    "5c:f7:e6": "Apple", "60:03:08": "Apple", "60:33:4b": "Apple",
    "60:69:44": "Apple", "60:8c:4a": "Apple", "60:a3:7d": "Apple",
    "60:c5:47": "Apple", "60:d9:c7": "Apple", "60:f8:1d": "Apple",
    "60:fa:cd": "Apple", "60:fe:c5": "Apple", "64:20:0c": "Apple",
    "64:76:ba": "Apple", "64:a3:cb": "Apple", "64:b0:a6": "Apple",
    "64:e6:82": "Apple", "68:5b:35": "Apple", "68:5e:dd": "Apple",
    "68:96:7b": "Apple", "68:9c:70": "Apple", "68:a8:6d": "Apple",
    "68:ab:1e": "Apple", "68:d9:3c": "Apple", "68:db:ca": "Apple",
    "68:fb:7e": "Apple", "6c:19:c0": "Apple", "6c:3e:6d": "Apple",
    "6c:40:08": "Apple", "6c:70:9f": "Apple", "6c:72:e7": "Apple",
    "6c:94:f8": "Apple", "6c:96:cf": "Apple", "6c:ab:31": "Apple",
    "6c:c2:6b": "Apple", "70:11:24": "Apple", "70:3e:ac": "Apple",
    "70:48:0f": "Apple", "70:56:81": "Apple", "70:73:cb": "Apple",
    "70:81:eb": "Apple", "70:a2:b3": "Apple", "70:cd:60": "Apple",
    "70:de:e2": "Apple", "70:ec:e4": "Apple", "74:1b:b2": "Apple",
    "74:42:8b": "Apple", "74:8d:08": "Apple", "74:e1:b6": "Apple",
    "74:e2:f5": "Apple", "78:31:c1": "Apple", "78:32:1b": "Apple",
    "78:3a:84": "Apple", "78:67:d7": "Apple", "78:6c:1c": "Apple",
    "78:7b:8a": "Apple", "78:88:6d": "Apple", "78:9f:70": "Apple",
    "78:a3:e4": "Apple", "78:ca:39": "Apple", "78:d7:5f": "Apple",
    "78:fd:94": "Apple", "7c:04:d0": "Apple", "7c:11:be": "Apple",
    "7c:6d:62": "Apple", "7c:d1:c3": "Apple", "7c:f0:5f": "Apple",
    "80:00:6e": "Apple", "80:49:71": "Apple", "80:92:9f": "Apple",
    "80:b0:3d": "Apple", "80:e6:50": "Apple", "80:ea:96": "Apple",
    "80:ed:2c": "Apple", "84:29:99": "Apple", "84:38:35": "Apple",
    "84:78:8b": "Apple", "84:85:06": "Apple", "84:89:ad": "Apple",
    "84:8e:0c": "Apple", "84:b1:53": "Apple", "84:fc:ac": "Apple",
    "84:fc:fe": "Apple", "88:63:df": "Apple", "88:66:a5": "Apple",
    "88:6b:6e": "Apple", "88:c6:63": "Apple", "88:cb:87": "Apple",
    "88:e8:7f": "Apple", "8c:00:6d": "Apple", "8c:29:37": "Apple",
    "8c:2d:aa": "Apple", "8c:58:77": "Apple", "8c:7b:9d": "Apple",
    "8c:7c:92": "Apple", "8c:85:90": "Apple", "8c:fa:ba": "Apple",
    "90:3c:92": "Apple", "90:72:40": "Apple", "90:84:0d": "Apple",
    "90:8d:6c": "Apple", "90:b0:ed": "Apple", "90:b2:1f": "Apple",
    "90:b6:86": "Apple", "90:fd:61": "Apple", "94:94:26": "Apple",
    "94:e9:6a": "Apple", "94:f6:a3": "Apple", "98:01:a7": "Apple",
    "98:03:d8": "Apple", "98:10:e8": "Apple", "98:46:0a": "Apple",
    "98:5a:eb": "Apple", "98:b8:e3": "Apple", "98:d6:bb": "Apple",
    "98:e0:d9": "Apple", "98:f0:ab": "Apple", "98:fe:94": "Apple",
    "9c:04:eb": "Apple", "9c:20:7b": "Apple", "9c:35:eb": "Apple",
    "9c:4f:da": "Apple", "9c:84:bf": "Apple", "9c:f3:87": "Apple",
    "9c:f4:8e": "Apple", "a0:78:17": "Apple", "a0:99:9b": "Apple",
    "a0:d7:95": "Apple", "a0:ed:cd": "Apple", "a4:5e:60": "Apple",
    "a4:67:06": "Apple", "a4:b1:97": "Apple", "a4:b8:05": "Apple",
    "a4:c3:61": "Apple", "a4:d1:8c": "Apple", "a4:d1:d2": "Apple",
    "a4:d9:31": "Apple", "a8:20:66": "Apple", "a8:5c:2c": "Apple",
    "a8:66:7f": "Apple", "a8:86:dd": "Apple", "a8:88:08": "Apple",
    "a8:8e:24": "Apple", "a8:96:8a": "Apple", "a8:bb:cf": "Apple",
    "a8:fa:d8": "Apple", "ac:29:3a": "Apple", "ac:3c:0b": "Apple",
    "ac:61:ea": "Apple", "ac:7f:3e": "Apple", "ac:87:a3": "Apple",
    "ac:bc:32": "Apple", "ac:cf:5c": "Apple", "ac:e4:b5": "Apple",
    "ac:fd:ec": "Apple", "b0:34:95": "Apple", "b0:48:1a": "Apple",
    "b0:65:bd": "Apple", "b0:70:2d": "Apple", "b0:9f:ba": "Apple",
    "b0:be:83": "Apple", "b0:c5:54": "Apple", "b0:ca:68": "Apple",
    "b4:18:d1": "Apple", "b4:8b:19": "Apple", "b4:f0:ab": "Apple",
    "b4:f6:1c": "Apple", "b8:17:c2": "Apple", "b8:41:a4": "Apple",
    "b8:44:d9": "Apple", "b8:53:ac": "Apple", "b8:63:4d": "Apple",
    "b8:78:2e": "Apple", "b8:8d:12": "Apple", "b8:c1:11": "Apple",
    "b8:c7:5d": "Apple", "b8:e8:56": "Apple", "b8:f6:b1": "Apple",
    "b8:ff:61": "Apple", "bc:3b:af": "Apple", "bc:52:b7": "Apple",
    "bc:54:36": "Apple", "bc:67:78": "Apple", "bc:6c:21": "Apple",
    "bc:92:6b": "Apple", "bc:9f:ef": "Apple", "bc:a9:20": "Apple",
    "bc:ec:5d": "Apple", "c0:1a:da": "Apple", "c0:63:94": "Apple",
    "c0:84:7a": "Apple", "c0:9f:42": "Apple", "c0:a5:3e": "Apple",
    "c0:cc:f8": "Apple", "c0:ce:cd": "Apple", "c0:d0:12": "Apple",
    "c4:2c:03": "Apple", "c4:b3:01": "Apple", "c8:1e:e7": "Apple",
    "c8:2a:14": "Apple", "c8:33:4b": "Apple", "c8:69:cd": "Apple",
    "c8:6f:1d": "Apple", "c8:85:50": "Apple", "c8:b5:b7": "Apple",
    "c8:bc:c8": "Apple", "c8:e0:eb": "Apple", "c8:f6:50": "Apple",
    "cc:08:8d": "Apple", "cc:20:e8": "Apple", "cc:25:ef": "Apple",
    "cc:29:f5": "Apple", "cc:44:63": "Apple", "cc:78:5f": "Apple",
    "d0:03:4b": "Apple", "d0:25:98": "Apple", "d0:33:11": "Apple",
    "d0:4f:7e": "Apple", "d0:81:7a": "Apple", "d0:a6:37": "Apple",
    "d0:c5:f3": "Apple", "d0:e1:40": "Apple", "d4:61:9d": "Apple",
    "d4:9a:20": "Apple", "d4:a3:3d": "Apple", "d4:f4:6f": "Apple",
    "d8:00:4d": "Apple", "d8:1d:72": "Apple", "d8:30:62": "Apple",
    "d8:8f:76": "Apple", "d8:96:95": "Apple", "d8:9e:3f": "Apple",
    "d8:a2:5e": "Apple", "d8:bb:2c": "Apple", "d8:cf:9c": "Apple",
    "dc:0c:5c": "Apple", "dc:2b:2a": "Apple", "dc:2b:61": "Apple",
    "dc:37:14": "Apple", "dc:41:5f": "Apple", "dc:56:e7": "Apple",
    "dc:86:d8": "Apple", "dc:9b:9c": "Apple", "dc:a4:ca": "Apple",
    "dc:a9:04": "Apple", "e0:33:8e": "Apple", "e0:5f:45": "Apple",
    "e0:66:78": "Apple", "e0:ac:cb": "Apple", "e0:b5:2d": "Apple",
    "e0:b9:ba": "Apple", "e0:c7:67": "Apple", "e0:c9:7a": "Apple",
    "e0:f5:c6": "Apple", "e4:25:e7": "Apple", "e4:8b:7f": "Apple",
    "e4:9a:dc": "Apple", "e4:c6:3d": "Apple", "e4:ce:8f": "Apple",
    "e4:e4:ab": "Apple", "e8:04:0b": "Apple", "e8:06:88": "Apple",
    "e8:80:2e": "Apple", "e8:8d:28": "Apple", "ec:35:86": "Apple",
    "ec:85:2f": "Apple", "f0:18:98": "Apple", "f0:24:75": "Apple",
    "f0:72:ea": "Apple", "f0:98:9d": "Apple", "f0:b4:79": "Apple",
    "f0:c1:f1": "Apple", "f0:cb:a1": "Apple", "f0:d1:a9": "Apple",
    "f0:db:e2": "Apple", "f0:dc:e2": "Apple", "f4:06:69": "Apple",
    "f4:1b:a1": "Apple", "f4:31:c3": "Apple", "f4:37:b7": "Apple",
    "f4:5c:89": "Apple", "f8:1e:df": "Apple", "f8:27:93": "Apple",
    "f8:62:14": "Apple", "f8:e9:4e": "Apple", "fc:25:3f": "Apple",
    "fc:e9:98": "Apple",
    # Foxconn / CLNTS (OEM for Dell, HP, Lenovo)
    "e8:65:38": "Foxconn", "58:cd:c9": "Foxconn", "44:fa:66": "Foxconn",
    "dc:56:7b": "Foxconn", "90:0f:0c": "Foxconn", "38:d5:7a": "Foxconn",
    "2c:98:11": "Foxconn", "ac:f2:3c": "Foxconn", "14:ac:60": "Foxconn",
    "84:9e:56": "Foxconn", "48:45:e6": "Foxconn", "78:46:5c": "Foxconn",
    "2c:9c:58": "Foxconn", "50:c2:e8": "Foxconn", "4c:23:38": "Foxconn",
    "cc:5e:f8": "Foxconn",
    # Samsung (Phone/Tablet)
    "00:21:19": "Samsung", "00:23:39": "Samsung", "00:23:d6": "Samsung",
    "00:23:d7": "Samsung", "00:24:54": "Samsung", "00:26:37": "Samsung",
    "00:e0:64": "Samsung", "08:08:c2": "Samsung", "08:21:ef": "Samsung",
    "08:37:3d": "Samsung", "08:d4:2b": "Samsung", "08:ec:a9": "Samsung",
    "0c:14:20": "Samsung", "10:1d:c0": "Samsung", "10:30:47": "Samsung",
    "14:49:e0": "Samsung", "14:89:fd": "Samsung", "18:3a:2d": "Samsung",
    "18:67:b0": "Samsung", "1c:66:aa": "Samsung", "20:13:e0": "Samsung",
    "20:6e:9c": "Samsung", "24:18:1d": "Samsung", "28:27:bf": "Samsung",
    "28:98:7b": "Samsung", "2c:ae:2b": "Samsung", "30:96:fb": "Samsung",
    "30:cb:f8": "Samsung", "34:23:ba": "Samsung", "34:aa:8b": "Samsung",
    "38:01:46": "Samsung", "38:0a:94": "Samsung", "38:2d:e8": "Samsung",
    "3c:5a:37": "Samsung", "40:0e:85": "Samsung", "44:6d:6c": "Samsung",
    "44:78:3e": "Samsung", "48:13:7e": "Samsung", "48:44:f7": "Samsung",
    "4c:bc:48": "Samsung", "50:01:bb": "Samsung", "50:32:75": "Samsung",
    "50:a4:d0": "Samsung", "54:92:be": "Samsung", "58:c3:8b": "Samsung",
    "5c:3c:27": "Samsung", "5c:a3:eb": "Samsung", "60:6b:bd": "Samsung",
    "64:77:91": "Samsung", "6c:f3:73": "Samsung", "70:f9:27": "Samsung",
    "74:45:ce": "Samsung", "78:25:ad": "Samsung", "78:47:1d": "Samsung",
    "78:52:1a": "Samsung", "78:bd:bc": "Samsung", "7c:0a:3f": "Samsung",
    "80:18:a7": "Samsung", "84:25:19": "Samsung", "84:38:38": "Samsung",
    "84:55:a5": "Samsung", "84:a4:66": "Samsung", "84:b5:41": "Samsung",
    "88:32:9b": "Samsung", "88:ad:d2": "Samsung", "8c:77:12": "Samsung",
    "90:18:7c": "Samsung", "94:01:c2": "Samsung", "94:35:0a": "Samsung",
    "94:51:03": "Samsung", "94:b8:6d": "Samsung", "98:0c:82": "Samsung",
    "98:39:8e": "Samsung", "98:52:b1": "Samsung", "9c:02:98": "Samsung",
    "9c:3a:af": "Samsung", "a0:04:60": "Samsung", "a0:07:98": "Samsung",
    "a0:b4:a5": "Samsung", "a0:cc:2b": "Samsung", "a4:08:ea": "Samsung",
    "a8:06:00": "Samsung", "a8:f2:74": "Samsung", "ac:5f:3e": "Samsung",
    "b0:47:bf": "Samsung", "b0:72:bf": "Samsung", "b0:c4:e7": "Samsung",
    "b0:df:3a": "Samsung", "b4:07:f9": "Samsung", "b4:3a:28": "Samsung",
    "b4:79:a7": "Samsung", "b8:57:d8": "Samsung", "b8:d7:af": "Samsung",
    "bc:20:a4": "Samsung", "bc:44:86": "Samsung", "bc:72:b1": "Samsung",
    "bc:76:70": "Samsung", "c0:97:27": "Samsung", "c0:bd:d1": "Samsung",
    "c4:42:02": "Samsung", "c4:73:1e": "Samsung", "c8:14:79": "Samsung",
    "c8:ba:94": "Samsung", "cc:07:ab": "Samsung", "d0:17:c2": "Samsung",
    "d0:22:be": "Samsung", "d0:59:e4": "Samsung", "d0:66:7b": "Samsung",
    "d4:88:90": "Samsung", "d8:57:ef": "Samsung", "d8:90:e8": "Samsung",
    "d8:c4:e9": "Samsung", "dc:71:44": "Samsung", "e4:12:1d": "Samsung",
    "e4:40:e2": "Samsung", "e4:58:b8": "Samsung", "e4:7c:f9": "Samsung",
    "e4:92:fb": "Samsung", "e8:3a:12": "Samsung", "e8:50:8b": "Samsung",
    "ec:1f:72": "Samsung", "ec:9b:f3": "Samsung", "f0:25:b7": "Samsung",
    "f0:5b:7b": "Samsung", "f0:e7:7e": "Samsung", "f4:09:d8": "Samsung",
    "f4:42:8f": "Samsung", "f4:7b:5e": "Samsung", "f8:04:2e": "Samsung",
    "f8:3f:51": "Samsung", "fc:a8:9a": "Samsung",
    # Xiaomi / Redmi (Phone)
    "00:9e:c8": "Xiaomi", "04:cf:8c": "Xiaomi", "0c:1d:af": "Xiaomi",
    "10:2a:b3": "Xiaomi", "14:f6:5a": "Xiaomi", "18:59:36": "Xiaomi",
    "20:47:da": "Xiaomi", "28:6c:07": "Xiaomi", "34:80:b3": "Xiaomi",
    "38:a4:ed": "Xiaomi", "3c:bd:3e": "Xiaomi", "44:23:7c": "Xiaomi",
    "50:64:2b": "Xiaomi", "58:44:98": "Xiaomi", "64:b4:73": "Xiaomi",
    "68:ab:bc": "Xiaomi", "74:23:44": "Xiaomi", "7c:1c:4e": "Xiaomi",
    "84:f3:eb": "Xiaomi", "8c:be:be": "Xiaomi", "98:fa:e3": "Xiaomi",
    "9c:99:a0": "Xiaomi", "a4:77:33": "Xiaomi", "ac:c1:ee": "Xiaomi",
    "b0:e2:35": "Xiaomi", "c4:0b:cb": "Xiaomi", "d8:63:75": "Xiaomi",
    "f0:b4:29": "Xiaomi", "f4:f5:db": "Xiaomi", "fc:64:ba": "Xiaomi",
    # OPPO / Realme / OnePlus (Phone)
    "00:41:0e": "OPPO", "00:45:e2": "OPPO", "08:4a:cf": "OPPO",
    "18:f0:e4": "OPPO", "1c:cc:d6": "OPPO", "28:a9:a0": "OPPO",
    "2c:5b:e1": "OPPO", "40:e3:d6": "OPPO", "44:16:22": "OPPO",
    "58:a2:b5": "OPPO", "5c:ea:1d": "OPPO", "6c:5c:3d": "OPPO",
    "74:d2:1d": "OPPO", "7c:03:ab": "OPPO", "80:ad:16": "OPPO",
    "84:de:a8": "OPPO", "88:19:08": "OPPO", "9c:28:f7": "OPPO",
    "a4:3b:fa": "OPPO", "a4:50:46": "OPPO", "ac:d6:18": "OPPO",
    "b4:a2:eb": "OPPO", "b8:f0:3c": "OPPO", "bc:54:fc": "OPPO",
    "c4:12:f5": "OPPO", "cc:2d:21": "OPPO", "d4:50:3f": "OPPO",
    "dc:6d:cd": "OPPO", "e0:1c:fc": "OPPO", "e8:61:7e": "OPPO",
    "ec:fa:f0": "OPPO", "f4:c6:13": "OPPO",
    # Vivo (Phone)
    "08:a9:5a": "Vivo", "24:e5:0f": "Vivo", "34:e8:94": "Vivo",
    "40:55:82": "Vivo", "48:ad:08": "Vivo", "60:21:01": "Vivo",
    "74:19:f8": "Vivo", "88:ea:a3": "Vivo", "ac:3b:77": "Vivo",
    "b4:ef:fa": "Vivo", "c8:f2:30": "Vivo", "d0:ab:d5": "Vivo",
    "e0:19:54": "Vivo",
    # Huawei (Phone/Laptop)
    "00:18:82": "Huawei", "00:1e:10": "Huawei", "00:25:68": "Huawei",
    "00:25:9e": "Huawei", "00:46:4b": "Huawei", "04:b0:e7": "Huawei",
    "04:c0:6f": "Huawei", "04:f9:38": "Huawei", "08:19:a6": "Huawei",
    "0c:37:dc": "Huawei", "10:44:00": "Huawei", "10:47:80": "Huawei",
    "14:30:04": "Huawei", "20:08:ed": "Huawei", "20:a6:80": "Huawei",
    "24:09:95": "Huawei", "24:69:a5": "Huawei", "28:3c:e4": "Huawei",
    "28:6e:d4": "Huawei", "2c:55:d3": "Huawei", "34:1e:6b": "Huawei",
    "38:4c:4f": "Huawei", "3c:47:11": "Huawei", "3c:fa:43": "Huawei",
    "40:4d:8e": "Huawei", "48:00:31": "Huawei", "48:3c:0c": "Huawei",
    "48:46:fb": "Huawei", "4c:8b:ef": "Huawei",
    "4c:b1:6c": "Huawei", "50:a7:2b": "Huawei", "54:25:ea": "Huawei",
    "58:60:5f": "Huawei", "5c:7d:5e": "Huawei", "60:de:44": "Huawei",
    "64:16:f0": "Huawei", "68:a0:f6": "Huawei", "6c:b7:49": "Huawei",
    "70:7b:e8": "Huawei", "74:88:2a": "Huawei", "78:1d:ba": "Huawei",
    "7c:60:97": "Huawei", "80:b6:55": "Huawei", "80:d0:9b": "Huawei",
    "84:a8:e4": "Huawei", "88:28:b3": "Huawei", "88:53:d4": "Huawei",
    "8c:34:fd": "Huawei", "90:17:ac": "Huawei", "94:04:9c": "Huawei",
    "94:77:2b": "Huawei", "98:e7:f5": "Huawei", "9c:28:ef": "Huawei",
    "9c:74:1a": "Huawei", "a0:8c:f8": "Huawei", "a4:71:74": "Huawei",
    "a4:99:47": "Huawei", "a8:ca:7b": "Huawei", "ac:61:75": "Huawei",
    "ac:cf:85": "Huawei", "b0:5b:67": "Huawei", "b4:30:52": "Huawei",
    "b4:cd:27": "Huawei", "b8:bc:1b": "Huawei", "bc:25:e0": "Huawei",
    "bc:76:96": "Huawei", "c0:70:09": "Huawei", "c4:05:28": "Huawei",
    "c4:86:e9": "Huawei", "c8:d1:5e": "Huawei", "cc:a2:23": "Huawei",
    "d0:7a:b5": "Huawei", "d4:6a:a8": "Huawei", "d4:b1:10": "Huawei",
    "d8:49:0b": "Huawei", "dc:d2:fc": "Huawei", "e0:24:7f": "Huawei",
    "e0:97:96": "Huawei", "e4:68:a3": "Huawei", "e4:77:23": "Huawei",
    "e8:cd:2d": "Huawei", "ec:23:3d": "Huawei", "ec:cb:30": "Huawei",
    "f4:63:1f": "Huawei", "f4:c7:14": "Huawei", "f4:e3:fb": "Huawei",
    "f8:01:13": "Huawei", "f8:4a:bf": "Huawei", "f8:e8:11": "Huawei",
    "fc:48:ef": "Huawei",
    # Dell
    "00:14:22": "Dell", "00:1a:a0": "Dell", "00:1e:4f": "Dell",
    "00:21:70": "Dell", "00:24:e8": "Dell", "14:18:77": "Dell",
    "18:03:73": "Dell", "18:a9:9b": "Dell", "18:db:f2": "Dell",
    "24:6e:96": "Dell", "34:17:eb": "Dell", "3c:97:0e": "Dell",
    "44:a8:42": "Dell", "48:4d:7e": "Dell", "50:9a:4c": "Dell",
    "54:bf:64": "Dell", "5c:26:0a": "Dell", "74:86:7a": "Dell",
    "74:e6:e2": "Dell", "78:2b:cb": "Dell", "80:18:44": "Dell",
    "84:7b:eb": "Dell", "84:8f:69": "Dell", "98:90:96": "Dell",
    "a4:1f:72": "Dell", "a4:ba:db": "Dell", "b0:83:fe": "Dell",
    "b4:e1:0f": "Dell", "bc:30:5b": "Dell", "c8:1f:66": "Dell",
    "d0:43:1e": "Dell", "d4:81:d7": "Dell", "d4:be:d9": "Dell",
    "e0:db:55": "Dell", "e4:43:4b": "Dell", "f0:1f:af": "Dell",
    "f4:8e:38": "Dell", "f8:b1:56": "Dell", "f8:ca:b8": "Dell",
    "f8:db:88": "Dell",
    # HP / Hewlett-Packard
    "00:0b:cd": "HP", "00:0e:7f": "HP", "00:0f:20": "HP",
    "00:12:79": "HP", "00:13:21": "HP", "00:14:38": "HP",
    "00:15:60": "HP", "00:17:08": "HP", "00:18:fe": "HP",
    "00:1a:4b": "HP", "00:1b:78": "HP", "00:1c:c4": "HP",
    "00:1e:0b": "HP", "00:1f:29": "HP", "00:21:5a": "HP",
    "00:22:64": "HP", "00:23:7d": "HP", "00:24:81": "HP",
    "00:25:b3": "HP", "00:26:55": "HP", "00:30:6e": "HP",
    "08:2e:5f": "HP", "10:1f:74": "HP", "10:60:4b": "HP",
    "14:02:ec": "HP", "14:58:d0": "HP", "18:a9:05": "HP",
    "1c:39:47": "HP", "1c:c1:de": "HP", "24:be:05": "HP",
    "28:80:23": "HP", "2c:27:d7": "HP", "2c:41:38": "HP",
    "2c:44:fd": "HP", "30:8d:99": "HP", "30:e1:71": "HP",
    "34:64:a9": "HP", "38:63:bb": "HP", "38:ea:a7": "HP",
    "3c:d9:2b": "HP", "40:b0:34": "HP", "44:31:92": "HP",
    "48:0f:cf": "HP", "48:df:37": "HP", "4c:39:09": "HP",
    "50:65:f3": "HP", "58:20:b1": "HP", "5c:b9:01": "HP",
    "64:51:06": "HP", "68:b5:99": "HP", "6c:3b:e5": "HP",
    "6c:c2:17": "HP", "70:10:6f": "HP", "74:46:a0": "HP",
    "78:ac:c0": "HP", "80:c1:6e": "HP", "84:34:97": "HP",
    "8c:dc:d4": "HP", "94:57:a5": "HP", "98:e7:f4": "HP",
    "9c:b6:54": "HP", "a0:1d:48": "HP", "a0:2b:b8": "HP",
    "a0:48:1c": "HP", "a4:5d:36": "HP", "a8:b1:3b": "HP",
    "ac:16:2d": "HP", "b0:5a:da": "HP", "b4:b5:2f": "HP",
    "b4:b6:76": "HP", "b8:af:67": "HP", "c0:14:b8": "HP",
    "c4:34:6b": "HP", "c8:cb:b8": "HP", "cc:3e:5f": "HP",
    "d0:bf:9c": "HP", "d4:c9:ef": "HP", "d8:9d:67": "HP",
    "d8:d3:85": "HP", "e4:11:5b": "HP", "e8:f7:24": "HP",
    "ec:8e:b5": "HP", "f0:92:1c": "HP", "f4:39:09": "HP",
    "fc:15:b4": "HP",
    # Lenovo
    "00:06:1b": "Lenovo", "00:09:2d": "Lenovo", "00:0a:e4": "Lenovo",
    "00:12:fe": "Lenovo", "00:1a:6b": "Lenovo", "04:7b:cb": "Lenovo",
    "10:a5:1d": "Lenovo", "1c:69:7a": "Lenovo",
    "20:7c:8f": "Lenovo", "28:d2:44": "Lenovo", "34:02:86": "Lenovo",
    "48:2a:e3": "Lenovo",
    "50:7b:9d": "Lenovo", "54:ab:3a": "Lenovo", "5c:c5:d4": "Lenovo",
    "68:f7:28": "Lenovo", "70:5a:0f": "Lenovo", "74:e5:43": "Lenovo",
    "78:e4:00": "Lenovo", "7c:7a:91": "Lenovo", "80:fa:5b": "Lenovo",
    "84:a6:c8": "Lenovo", "8c:16:45": "Lenovo", "90:2e:1c": "Lenovo",
    "98:fa:9b": "Lenovo", "a4:34:d9": "Lenovo", "a4:c4:94": "Lenovo",
    "a8:6b:ad": "Lenovo", "ac:e2:d3": "Lenovo", "b4:6b:fc": "Lenovo",
    "c8:5b:76": "Lenovo", "c8:dd:c9": "Lenovo", "d0:57:7b": "Lenovo",
    "d8:fc:93": "Lenovo", "e0:2b:e9": "Lenovo",
    "e4:54:e8": "Lenovo", "e8:6a:64": "Lenovo", "ec:b1:d7": "Lenovo",
    "f0:03:8c": "Lenovo", "f8:75:a4": "Lenovo",
    # ASUS
    "00:0c:6e": "ASUS", "00:0e:a6": "ASUS", "00:11:2f": "ASUS",
    "00:13:d4": "ASUS", "00:15:f2": "ASUS", "00:17:31": "ASUS",
    "00:1a:92": "ASUS", "00:1d:60": "ASUS", "00:1e:8c": "ASUS",
    "00:1f:c6": "ASUS", "00:22:15": "ASUS", "00:23:54": "ASUS",
    "00:24:8c": "ASUS", "00:26:18": "ASUS", "04:92:26": "ASUS",
    "08:60:6e": "ASUS", "0c:9d:92": "ASUS", "10:7b:44": "ASUS",
    "14:dd:a9": "ASUS", "1c:87:2c": "ASUS", "1c:b7:2c": "ASUS",
    "20:cf:30": "ASUS", "2c:4d:54": "ASUS", "2c:56:dc": "ASUS",
    "2c:fd:a1": "ASUS", "30:5a:3a": "ASUS", "30:85:a9": "ASUS",
    "34:97:f6": "ASUS", "38:2c:4a": "ASUS", "38:d5:47": "ASUS",
    "3c:7c:3f": "ASUS", "40:16:7e": "ASUS", "40:b0:76": "ASUS",
    "48:5b:39": "ASUS", "4c:ed:fb": "ASUS", "50:46:5d": "ASUS",
    "54:04:a6": "ASUS", "54:a0:50": "ASUS", "60:45:cb": "ASUS",
    "6c:72:20": "ASUS", "70:8b:cd": "ASUS", "74:d0:2b": "ASUS",
    "78:24:af": "ASUS", "90:e6:ba": "ASUS", "a4:2b:b0": "ASUS",
    "ac:22:0b": "ASUS", "ac:9e:17": "ASUS", "b0:6e:bf": "ASUS",
    "bc:ee:7b": "ASUS", "c4:60:44": "ASUS", "c8:60:00": "ASUS",
    "d4:5d:64": "ASUS", "d8:50:e6": "ASUS", "e0:3f:49": "ASUS",
    "e0:cb:4e": "ASUS", "f0:79:59": "ASUS", "f4:6d:04": "ASUS",
    "fc:c2:33": "ASUS",
    # Sony (TV/Device)
    "88:c9:e8": "Sony",
    # Cisco (Network)
    "00:15:5d": "Microsoft", "54:8a:ba": "Cisco", "64:00:f1": "Cisco",
    "d4:e8:80": "Cisco", "cc:b6:c8": "Cisco",
}

# Device type classification
DEVICE_TYPES = {
    "Intel": "laptop", "Liteon": "laptop", "AzureWave": "laptop",
    "Foxconn": "laptop", "Dell": "laptop", "HP": "laptop",
    "Lenovo": "laptop", "ASUS": "laptop",
    "Apple": "laptop/phone",
    "Samsung": "phone", "Xiaomi": "phone", "OPPO": "phone",
    "Vivo": "phone", "Huawei": "phone/laptop",
    "Sony": "tv", "Cisco": "network", "Microsoft": "network",
}


def snmp_walk(host, community, oid, timeout=15, retries=2):
    """Run snmpwalk and return {index: value} dict."""
    cmd = ['snmpwalk', '-v2c', '-c', community, '-t', str(timeout),
           '-r', str(retries), host, oid]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * (retries + 1) * 3, errors='replace')
    except subprocess.TimeoutExpired:
        return {}

    data = {}
    for line in result.stdout.strip().split('\n'):
        if ' = ' not in line:
            continue
        parts = line.split(' = ', 1)
        oid_part, val_part = parts[0].strip(), parts[1].strip()

        idx_match = re.search(r'\.(\d+\.\d+\.\d+\.\d+\.\d+\.\d+)$', oid_part)
        if not idx_match:
            continue
        idx = idx_match.group(1)

        if 'STRING:' in val_part:
            val = val_part.split('STRING:', 1)[1].strip().strip('"')
        elif 'IpAddress:' in val_part:
            val = val_part.split('IpAddress:', 1)[1].strip()
        elif 'INTEGER:' in val_part:
            val = val_part.split('INTEGER:', 1)[1].strip()
        elif 'Hex-STRING:' in val_part:
            val = val_part.split('Hex-STRING:', 1)[1].strip()
        else:
            val = val_part
        data[idx] = val
    return data


def idx_to_mac(idx):
    """Convert SNMP decimal index to MAC address string."""
    parts = idx.split('.')
    if len(parts) == 6:
        return ':'.join(f'{int(p):02x}' for p in parts)
    return idx


def lookup_vendor(mac):
    """Lookup vendor from local OUI DB."""
    oui = mac[:8].lower()
    return OUI_DB.get(oui, "Unknown")


def lookup_vendor_api(mac):
    """Lookup vendor via macvendors.com API (rate limited)."""
    import urllib.request
    try:
        url = f"https://api.macvendors.com/{mac[:8]}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode().strip()
    except Exception:
        return None


def classify_device(vendor):
    """Classify device type based on vendor."""
    return DEVICE_TYPES.get(vendor, "unknown")


def scan_wlc(host, community, vendor_api=False):
    """Scan WLC via SNMP and return list of client dicts."""
    # Cisco WLC SNMP OIDs (airespace MIB)
    OIDS = {
        'ip': '1.3.6.1.4.1.14179.2.1.4.1.2',
        'username': '1.3.6.1.4.1.14179.2.1.4.1.3',
        'ssid': '1.3.6.1.4.1.14179.2.1.4.1.7',
        'ap_mac': '1.3.6.1.4.1.14179.2.1.4.1.4',
        'protocol': '1.3.6.1.4.1.14179.2.1.4.1.25',
    }

    print(f"[*] Scanning WLC {host} (community: {community})...", file=sys.stderr)

    # Parallel SNMP walks
    results = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for name, oid in OIDS.items():
            print(f"  [>] Walking {name}...", file=sys.stderr)
            futures[executor.submit(snmp_walk, host, community, oid)] = name
        for future in as_completed(futures):
            name = futures[future]
            results[name] = future.result()
            print(f"  [+] {name}: {len(results[name])} entries", file=sys.stderr)

    # Also get AP names for location mapping
    print("  [>] Walking AP names...", file=sys.stderr)
    ap_names = snmp_walk(host, community, '1.3.6.1.4.1.14179.2.2.1.1.3')

    # Build client list
    clients = []
    api_cache = {}
    for idx, ip in results.get('ip', {}).items():
        mac = idx_to_mac(idx)
        vendor = lookup_vendor(mac)

        if vendor == "Unknown" and vendor_api:
            oui = mac[:8]
            if oui not in api_cache:
                v = lookup_vendor_api(mac)
                api_cache[oui] = v or "Unknown"
                time.sleep(0.5)  # rate limit
            vendor = api_cache[oui]

        device_type = classify_device(vendor)
        username = results.get('username', {}).get(idx, '')
        ssid = results.get('ssid', {}).get(idx, '')
        protocol = results.get('protocol', {}).get(idx, '')

        # Determine network segment
        if ip.startswith('10.22.'):
            segment = 'staff/internal'
        elif ip.startswith('10.33.'):
            segment = 'student'
        else:
            segment = 'other'

        clients.append({
            'mac': mac,
            'ip': ip,
            'vendor': vendor,
            'device_type': device_type,
            'username': username,
            'ssid': ssid,
            'protocol': protocol,
            'segment': segment,
        })

    print(f"\n[+] Total clients: {len(clients)}", file=sys.stderr)
    return clients, dict(ap_names)


def filter_clients(clients, filter_type):
    """Filter clients by device type."""
    if filter_type == 'all':
        return clients
    elif filter_type == 'laptop':
        return [c for c in clients if 'laptop' in c['device_type']]
    elif filter_type == 'phone':
        return [c for c in clients if 'phone' in c['device_type']]
    elif filter_type == 'staff':
        return [c for c in clients if c['segment'] == 'staff/internal']
    elif filter_type == 'student':
        return [c for c in clients if c['segment'] == 'student']
    elif filter_type == 'unknown':
        return [c for c in clients if c['vendor'] == 'Unknown']
    return clients


def print_table(clients):
    """Print clients as formatted table."""
    header = f"{'MAC':<18} {'IP':<16} {'VENDOR':<12} {'TYPE':<13} {'USERNAME':<25} {'SSID':<22} {'SEGMENT':<10}"
    print(header)
    print("-" * len(header))
    for c in sorted(clients, key=lambda x: (x['segment'], x['ip'])):
        print(f"{c['mac']:<18} {c['ip']:<16} {c['vendor']:<12} {c['device_type']:<13} {c['username']:<25} {c['ssid']:<22} {c['segment']:<10}")


def print_summary(clients):
    """Print summary statistics."""
    by_vendor = defaultdict(int)
    by_type = defaultdict(int)
    by_segment = defaultdict(int)
    by_ssid = defaultdict(int)

    for c in clients:
        by_vendor[c['vendor']] += 1
        by_type[c['device_type']] += 1
        by_segment[c['segment']] += 1
        by_ssid[c['ssid'] or '(empty)'] += 1

    print(f"\n{'='*50}")
    print(f"  SCAN SUMMARY - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")
    print(f"\nTotal clients: {len(clients)}")

    print("\n--- By Device Type ---")
    for t, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {t:<15} {count:>5}")

    print("\n--- By Vendor (top 20) ---")
    for v, count in sorted(by_vendor.items(), key=lambda x: -x[1])[:20]:
        print(f"  {v:<15} {count:>5}")

    print("\n--- By Segment ---")
    for s, count in sorted(by_segment.items(), key=lambda x: -x[1]):
        print(f"  {s:<15} {count:>5}")

    print("\n--- By SSID ---")
    for s, count in sorted(by_ssid.items(), key=lambda x: -x[1]):
        print(f"  {s:<22} {count:>5}")


def main():
    parser = argparse.ArgumentParser(
        description='WiFi Client Inventory Scanner - Extract laptop/mobile devices from Cisco WLC via SNMP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --wlc 10.22.64.6                          # Scan with defaults
  %(prog)s --wlc 10.22.64.6 --filter laptop           # Only laptops
  %(prog)s --wlc 10.22.64.6 --filter staff             # Only staff devices
  %(prog)s --wlc 10.22.64.6 --format json -o out.json  # JSON output
  %(prog)s --wlc 10.22.64.6 --format csv -o out.csv    # CSV output
  %(prog)s --wlc 10.22.64.6 --vendor-lookup            # API vendor lookup for unknowns
        """)

    parser.add_argument('--wlc', required=True, help='WLC IP address')
    parser.add_argument('--community', '-c', default='public', help='SNMP community string (default: public)')
    parser.add_argument('--filter', '-f', default='all',
                        choices=['all', 'laptop', 'phone', 'staff', 'student', 'unknown'],
                        help='Filter by device type or segment')
    parser.add_argument('--format', default='table', choices=['table', 'json', 'csv', 'ip-only'],
                        help='Output format')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--vendor-lookup', action='store_true',
                        help='Use macvendors.com API for unknown OUIs (slow, rate-limited)')
    parser.add_argument('--summary', '-s', action='store_true', help='Show summary statistics')
    parser.add_argument('--save-loot', help='Save all data to loot directory')

    args = parser.parse_args()

    clients, ap_names = scan_wlc(args.wlc, args.community, args.vendor_lookup)
    filtered = filter_clients(clients, args.filter)

    print(f"\n[+] Showing {len(filtered)}/{len(clients)} clients (filter: {args.filter})\n", file=sys.stderr)

    out = open(args.output, 'w') if args.output else sys.stdout

    if args.format == 'table':
        print_table(filtered)
    elif args.format == 'json':
        json.dump(filtered, out, indent=2)
        print(file=out)
    elif args.format == 'csv':
        writer = csv.DictWriter(out, fieldnames=['mac', 'ip', 'vendor', 'device_type', 'username', 'ssid', 'protocol', 'segment'])
        writer.writeheader()
        writer.writerows(filtered)
    elif args.format == 'ip-only':
        for c in sorted(filtered, key=lambda x: x['ip']):
            print(c['ip'], file=out)

    if args.output:
        out.close()
        print(f"\n[+] Output saved to {args.output}", file=sys.stderr)

    if args.summary:
        print_summary(filtered)

    if args.save_loot:
        os.makedirs(args.save_loot, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')

        with open(os.path.join(args.save_loot, f'clients_{ts}.json'), 'w') as f:
            json.dump(clients, f, indent=2)

        with open(os.path.join(args.save_loot, f'laptops_{ts}.txt'), 'w') as f:
            for c in filter_clients(clients, 'laptop'):
                f.write(f"{c['ip']}\n")

        with open(os.path.join(args.save_loot, f'phones_{ts}.txt'), 'w') as f:
            for c in filter_clients(clients, 'phone'):
                f.write(f"{c['ip']}\n")

        with open(os.path.join(args.save_loot, f'staff_{ts}.txt'), 'w') as f:
            for c in filter_clients(clients, 'staff'):
                f.write(f"{c['mac']}|{c['ip']}|{c['username']}|{c['ssid']}\n")

        with open(os.path.join(args.save_loot, f'ap_names_{ts}.txt'), 'w') as f:
            for idx, name in sorted(ap_names.items()):
                f.write(f"{name}\n")

        print(f"[+] Loot saved to {args.save_loot}/", file=sys.stderr)


if __name__ == '__main__':
    main()
