import csv
import sys

# Define the file path
CSV_file = sys.argv[1]

# Function to filter out deny rules
def filter_deny_rules(row):
    return 'allow' in str(row)

# Function to check if source is specified
def has_specified_source(rule):
    return rule['Source (Addresses)'] != "['any']"

# Function to check if destination is a range
def is_destination_range(rule):
    return '/' in rule['Destination (Addresses)']

# Arrays to store results
defined_src_to_any_destination = []
defined_src_to_specific_host_any_port = []  # Renamed variable
defined_src_to_destination_range = []
any_src_to_any_destination = []
any_src_to_destination_range = []

# Open the CSV file and read it into memory, filtering out deny rules
with open(CSV_file, 'r') as file:
    # Read the CSV file and filter out deny rules
    filtered_rows = filter(filter_deny_rules, csv.DictReader(file))
    
    # Iterate over each row in the filtered CSV
    for row in filtered_rows:
        # Apply checks and append results to the correct arrays
        
        # Check if source is specified and destination is any IP
        if has_specified_source(row) and row['Destination (Addresses)'] == "0.0.0.0/0":
            defined_src_to_any_destination.append(row['Name'])
        
        # Check if source is specified and destination is a specific host with any port
        # Assuming Destination (Alias) contains host names
        elif has_specified_source(row) and row['Destination (Alias)'] != "['any']" and row['Ports'] == "0-65535 (any)":
            defined_src_to_specific_host_any_port.append(row['Name'])  # Updated variable name
        
        # Check if source is specified and destination is a range
        elif has_specified_source(row) and is_destination_range(row):
            defined_src_to_destination_range.append(row['Name'])
        
        # Check if source is 'any' and destination is 'any'
        elif row['Source (Addresses)'] == "['any']" and row['Destination (Addresses)'] == "0.0.0.0/0":
            any_src_to_any_destination.append(row['Name'])
        
        # Check if source is 'any' and destination is a range
        elif row['Source (Addresses)'] == "['any']" and is_destination_range(row):
            any_src_to_destination_range.append(row['Name'])


def customPrint(arr):
    for line in arr:
        print(line)

# Print the results
print("Defined Source to Any Destination:")
customPrint(defined_src_to_any_destination)
print("\nDefined Source to Specific Host with Any Port:")
customPrint(defined_src_to_specific_host_any_port)  # Updated variable name
print("\nDefined Source to Destination Range:")
customPrint(defined_src_to_destination_range)
print("\nAny Source to Any Destination:")
customPrint(any_src_to_any_destination)
print("\nAny Source to Destination Range:")
customPrint(any_src_to_destination_range)
