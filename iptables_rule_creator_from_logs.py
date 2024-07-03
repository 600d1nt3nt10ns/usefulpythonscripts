#!/usr/bin/python3

import re
from collections import defaultdict

# This is python script for generation of iptables INPUT rules based on log records on certain device
# For log records generation please use:
# iptables -A INPUT -s 192.168.1.0/24 -d 192.168.1.0/24 -j LOG --log-prefix "fp=INPUT a=LAN_FILTER" --log-level 6

# Parse input file and get connections
def parse_log_input(logs):
    pattern = re.compile(r'.+fp=INPUT a=LAN_FILTER.+SRC=(\d+\.\d+\.\d+\.\d+) DST=(\d+\.\d+\.\d+\.\d+).+PROTO=(.+) SPT=(\d+) DPT=(\d+) .+')
    connections = pattern.findall(logs)
    return connections

def parse_wildcarded_input(input_str):
    pattern = re.compile(r'(\w+)-(\d+\.\d+\.\d+\.\d+):(\d+|x)->(\d+\.\d+\.\d+\.\d+):(\d+|x)')
    connections = pattern.findall(input_str)
    return connections

# Check dynamic ports for wildcard marking
def is_dynamic_port(port):
    dynamic_port_range = range(30000, 65536)
    return int(port) in dynamic_port_range

# Substitute dynamic ports with wildcards and filter similar records
def substitute_dynamic_ports_with_wildcard(connections):
    wildcarded_flow = []
    for src_ip, dst_ip, protocol, src_port, dst_port in connections:
        if is_dynamic_port(dst_port):
            dst_port = "x"
        if is_dynamic_port(src_port):
            src_port = "x"
        wildcarded_flow.append(f"{protocol}-{src_ip}:{src_port}->{dst_ip}:{dst_port}")
    return(wildcarded_flow)

# Generate iptables_rules
def generate_iptables_rules(wildcarded_flow):
    rules_dict = defaultdict(list)
    input_for_rules = parse_wildcarded_input(";".join(wildcarded_flow))
    for protocol, src_ip, src_port, dst_ip, dst_port in input_for_rules:
        if src_port == "x":
            src_rule = f"-s {src_ip}"
        else:
            src_rule = f"-s {src_ip} --sport {src_port}"
        if dst_port == "x":
            dst_rule = f"-d {dst_ip}"
        else:
            dst_rule = f"-d {dst_ip} --dport {dst_port}"
        rules_dict[dst_ip].append(f"iptables -A INPUT -p {protocol.lower()} -m {protocol.lower()} {src_rule} {dst_rule} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")
    return rules_dict

# Read flow file
with open("syslog_out.txt", "r") as logs:
    loglines = ''.join(logs.readlines())
    connections = parse_log_input(loglines)

# Create wildcarded flow
wildcarded_flow = substitute_dynamic_ports_with_wildcard(connections)

# Create statistics of rule usage

wildcarded_flow_set = set(wildcarded_flow)
statistics_dict = {}
for flow in wildcarded_flow_set:
    flow_matches = wildcarded_flow.count(flow)
    statistics_dict[flow] = int(flow_matches)

statistics_dict_sorted = dict(sorted(statistics_dict.items(), key=lambda item: item[1], reverse=True))
print("#Rule matching statistics for order generation:")
for flow in statistics_dict_sorted:
    print(f"{flow}:{statistics_dict_sorted[flow]}")

wildcarded_flow_ordered = statistics_dict_sorted.keys()

# Generate iptables rules
iptables_rules = generate_iptables_rules(wildcarded_flow_ordered)

# Print generated iptables rules to a file
with open("generated_iptable_rules_from_logs.txt", "w") as generated_iptables_rules:
    print("#Rule matching statistics for order generation:", file=generated_iptables_rules)
    for flow in statistics_dict_sorted:
        print(f"{flow}:{statistics_dict_sorted[flow]}", file=generated_iptables_rules)
    print("#Ordered rules:", file=generated_iptables_rules)
    for dst in iptables_rules:
        print(f"#####{dst}#####", file=generated_iptables_rules)
        for rule in iptables_rules[dst]:
            print(rule, file=generated_iptables_rules)
