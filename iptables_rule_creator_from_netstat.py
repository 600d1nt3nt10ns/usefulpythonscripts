#!/usr/bin/python3

import re
from collections import defaultdict

# This is python script for generation of iptables INPUT rules based on netstat results inside a subnet
# use "netstat -tan | awk '$4 ~ /192\.168\.1\./ && $5 ~ /192\.168\.1\./ {print $4 "->" $5}' | sort | uniq > all_flow_tcp.txt" to get the input for the script

# Parse input file and get connections
def parse_input(input_str):
    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+):(\d+|x)->(\d+\.\d+\.\d+\.\d+):(\d+|x)')
    connections = pattern.findall(input_str)
    return connections

# Check dynamic ports for wildcard marking
def is_dynamic_port(port):
    dynamic_port_range = range(30000, 65536)
    return int(port) in dynamic_port_range

# Substitute dynamic ports with wildcards and filter similar records
def substitute_dynamic_ports_with_wildcard(connections):
    wildcarded_flow = []
    for src_ip, src_port, dst_ip, dst_port in connections:
        if is_dynamic_port(dst_port):
            dst_port = "x"
        if is_dynamic_port(src_port):
            src_port = "x"
        wildcarded_flow.append(f"{src_ip}:{src_port}->{dst_ip}:{dst_port}")
    return(wildcarded_flow)

# Generate iptables_rules
def generate_iptables_rules(wildcarded_flow):
    rules_dict = defaultdict(list)
    input_for_rules = parse_input(";".join(wildcarded_flow))
    for src_ip, src_port, dst_ip, dst_port in input_for_rules:
        if src_port == "x":
            src_rule = f"-s {src_ip}"
        else:
            src_rule = f"-s {src_ip} --sport {src_port}"
        if dst_port == "x":
            dst_rule = f"-d {dst_ip}"
        else:
            dst_rule = f"-d {dst_ip} --dport {dst_port}"
        rules_dict[dst_ip].append(f"iptables -A INPUT -p tcp -m tcp {src_rule} {dst_rule} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")
    return rules_dict

# Read flow file
with open("all_flow_tcp.txt", "r") as netstat:
    flow = ''.join(netstat.readlines())
    connections = parse_input(flow)

# Create wildcarded flow
wildcarded_flow = substitute_dynamic_ports_with_wildcard(connections)

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
with open("generated_iptable_rules_from_netstat.txt", "w") as generated_iptables_rules:
    print("#Rule matching statistics for order generation:", file=generated_iptables_rules)
    for flow in statistics_dict_sorted:
        print(f"{flow}:{statistics_dict_sorted[flow]}", file=generated_iptables_rules)
    print("#Ordered rules:", file=generated_iptables_rules)
    for dst in iptables_rules:
        print(f"#####{dst}#####", file=generated_iptables_rules)
        for rule in iptables_rules[dst]:
            print(rule, file=generated_iptables_rules)ˇ
