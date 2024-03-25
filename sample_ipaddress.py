#!/usr/bin/python
# -*- coding: utf-8 -*-

import ipaddress
import logging
import re

import yaml

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


def ip_in_networks(ip_address, networks):
    """
    Parameters:
        ip_address (str): IP address to check
        networks (list): list of networks to check

    Returns:
        (bool): if IP is belongs to any network
    """
    ip = ipaddress.ip_address(ip_address)
    for network in networks:
        if ip in network:
            return True
    return False


bogons = set()
own_networks = set()
stopforumspam_ips = set()
blocklist_net_ua_ips = set()

bogons = set(load_data_from_yaml("bogons.yaml"))
own_networks = set(load_data_from_yaml("own_networks.yaml"))
ipaddress_own_networks = [ipaddress.ip_network(network) for network in own_networks]
ipaddress_bogons = [ipaddress.ip_network(network) for network in bogons]
stopforumspam_ips.update(load_data_from_ipset("stopforumspam.ipset"))
blocklist_net_ua_ips.update(load_data_from_ipset("blocklist_net_ua.ipset"))
to_block = {}
for ip in stopforumspam_ips:
    to_block[ip] = ["stopforumspam"]
for ip in blocklist_net_ua_ips:
    if to_block.get(ip):
        to_block[ip].append("blocklist_net_ua")
    else:
        to_block[ip] = ["blocklist_net_ua"]

for ip in to_block:
    if ip_in_networks(ip, ipaddress_own_networks):
        print(f"{ip} is one of our networks")
    if ip_in_networks(ip, ipaddress_bogons):
        print(f"{ip} is bogon")
    print(f"{ip} is on lists {to_block[ip]}")
