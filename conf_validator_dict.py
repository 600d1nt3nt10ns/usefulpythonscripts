#!/usr/bin/python3

import os
from collections import defaultdict

# Find conf files in path

print("This is configuration validation script to find needed and not needed elements in device configuration")
validate_devices = input("Enter hostname or string to match the configurations: ")
path = "/replace/me"
files = os.listdir(path)
confs_to_validate = []
for file in files:
    if validate_devices in file:
        confs_to_validate.append(file)
    else:
        pass

result_count = len(confs_to_validate)
if int(result_count) != 0:
    print("#################################################################")
    input(f"Search {validate_devices} matches {result_count} device. Press enter to continue!")
    print("#################################################################")
else:
    print("No match was found!")
    exit()

# Dicts

print("Characteristics needed in configuration: ")

# What is needed in configuration
validation_dict_needed = {
    "element1": "configuration_row_needed",
    "element2": "configuration_row_needed"
}


for element in validation_dict_needed:
    print(f"{element}")
    print(f" {validation_dict_needed[element]}")

print("#################################################################")

print("Characteristics not needed in configuration: ")

# What is not needed in configuration
validation_dict_not_needed = {
    "element3": "configuration_row_not_needed",
    "element4": "configuration_row_not_needed",
}

for element in validation_dict_not_needed:
    print(f"{element}")
    print(f" {validation_dict_not_needed[element]}")

print("#################################################################")

validation_results = defaultdict()

for conf in confs_to_validate:
    with open(path + "/" + conf, "r") as conf_file:
        conf_lines = conf_file.readlines()
        device = conf
        validation_results[device] = set()
        for line in conf_lines:
            line = line.strip("\n")
            # Needed
            for element in validation_dict_needed:
                value = validation_dict_needed[element]
                if value in line:
                    validation_results[device].add(element)
            # Not needed
            for element in validation_dict_not_needed:
                value = validation_dict_not_needed[element]
                if value in line:
                    validation_results[device].add(element)

# Print results

print("Mismatching characteristics found: ")

for device in validation_results:
    print("#################################################################")
    print(f"{device}: ")
    missing_elements = set(validation_dict_needed.keys()) ^ validation_results[device]
    for element in missing_elements:
        print(f"    -{element}")
