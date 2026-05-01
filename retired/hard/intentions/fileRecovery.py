#!/usr/bin/env python3
import os, subprocess  # Import the necessary libraries.
import hashlib
import argparse

# Create an ArgumentParser object to handle script arguments.
parser = argparse.ArgumentParser(description='Recover file using /opt/scanner/scanner.')
# Add arguments for file to recover and output file. These are required arguments.
parser.add_argument('-f', '--file', required=True, help='The file to recover.')
parser.add_argument('-o', '--output', required=True, help='The output file.')
args = parser.parse_args()  # Parse the input arguments.

filename = args.file  # File to recover.
output = args.output  # Output file name.

# Define a function to scan the file using an external scanner command.
def scan_file(num_bytes):
    # Prepare the scanner command.
    command = f"/opt/scanner/scanner -c {filename} -p -l {num_bytes} -s a".split()
    # Run the command and wait for it to complete.
    popen = subprocess.Popen(command, stdout=subprocess.PIPE)
    popen.wait()
    # Get the command output.
    output = popen.stdout.read().decode("utf-8")
    # Extract the hash value from the output.
    hash = output.split(" ")[-1]
    return hash

# Main execution starts here.
i = 1  # Initialize counter.
file_so_far = bytearray()  # Initialize the byte array to hold the file content.

# Start a loop to continuously attempt recovery.
while True:
    hash = scan_file(i).strip()  # Get the hash of the current chunk of file.
    found = False  # Flag to indicate if a match is found.

    # Try each possible byte value.
    for j in range(0x01, 0xff):
        byte = bytes([j])  # Convert integer to byte.
        attempt = file_so_far.copy()  # Make a copy of the current file content.

        # Append the current byte to the attempt.
        attempt += bytearray(byte)
        # Calculate the MD5 hash of the attempt.
        new_hash = hashlib.md5(attempt).hexdigest()

        # If the hashes match, update the file content and break the loop.
        if new_hash == hash:
            file_so_far = attempt
            found = True
            break

    # If no matching byte is found, print an error and break the main loop.
    if not found:
        print("ERROR: could not find valid byte")
        break

    i += 1  # Increment the counter.

# Write the recovered file content to the output file.
with open(output, "wb") as f:
    f.write(file_so_far)
