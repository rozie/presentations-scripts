#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import re

import yaml
from cidr_trie import PatriciaTrie

logger = logging.getLogger(__name__)


def load_data_from_yaml(yamlfile):
    """
    Parameters:
        yamlfile (str): name of the yaml file to read
    Returns:
        data (list): networks from the file
    """
    try:
        with open(yamlfile, "r") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.error("Couldn't read file %s", e)
    return data


def load_data_from_ipset(ipsetfile):
    """
    Parameters:
        ipsetfile (str): name of the file to read
    Returns:
        data (set): IP addresses
    """
    data = set()
    try:
        with open(ipsetfile, "r") as f:
            lines = f.read().splitlines()
        for line in lines:
            if re.search(r"^(\d+\.){3}\d+$", line):
                data.add(line)
    except Exception as e:
        logger.error("Couldn't read file %s", e)
    return data


bogons = set()
own_networks = set()
stopforumspam_ips = set()
blocklist_net_ua_ips = set()

bogons = set(load_data_from_yaml("bogons.yaml"))
own_networks = set(load_data_from_yaml("own_networks.yaml"))
stopforumspam_ips.update(load_data_from_ipset("stopforumspam.ipset"))
blocklist_net_ua_ips.update(load_data_from_ipset("blocklist_net_ua.ipset"))
to_block = {}

trie = PatriciaTrie()
for net in bogons:
    trie.insert(net, "bogons")
for net in own_networks:
    trie.insert(net, "own_network")
for ip in stopforumspam_ips:
    trie.insert(ip, "stopforumspam")
for ip in blocklist_net_ua_ips:
    trie.insert(ip, "blocklist_net_ua")

for ip in stopforumspam_ips:
    to_block[ip] = ["stopforumspam"]
for ip in blocklist_net_ua_ips:
    if to_block.get(ip):
        to_block[ip].append("blocklist_net_ua")
    else:
        to_block[ip] = ["blocklist_net_ua"]

for ip in to_block:
    contained_in = set(nodes[1] for nodes in trie.find_all(ip))
    if "own_network" in contained_in:
        print(f"{ip} is one of our networks")
    if "bogons" in contained_in:
        print(f"{ip} is bogon")
    print(f"{ip} is on lists {to_block[ip]}")

