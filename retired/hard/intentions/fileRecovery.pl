#!/usr/bin/perl
use strict;  # Enable strict mode to catch possible errors.
use warnings;  # Enable warnings to catch potential problems.
use Digest::MD5 qw(md5_hex);  # Use MD5 hashing algorithm.
use Getopt::Long qw(GetOptions);  # Use GetOptions for command line arguments.

# Declare variables for file to recover and output file.
my $filename;
my $output;

# Handle command line arguments with GetOptions.
GetOptions(
    'file|f=s' => \$filename,  # Get file name to recover.
    'output|o=s' => \$output   # Get name of output file.
) or die "Usage: $0 --file FILE --output OUTPUT\n";  # If arguments are not provided, print usage and exit.

# Define function to scan file.
sub scan_file {
    my ($num_bytes) = @_;  # Get the number of bytes to read.
    # Prepare the scanner command.
    my $command = "/opt/scanner/scanner -c $filename -p -l $num_bytes -s a";
    # Execute the command and capture its output.
    my $output = `$command`;
    # Split the output into words.
    my @words = split ' ', $output;
    my $hash = $words[-1];    # Get the last word (the hash).
    return $hash;  # Return the hash.
}

# Main program starts here.
my $i = 1;  # Initialize counter.
my $file_so_far = "";  # Initialize the file content.

# Start a loop to continuously attempt recovery.
while (1) {
    my $hash = scan_file($i);  # Get the hash of the current file chunk.
    $hash =~ s/\s+$//;   # Remove trailing spaces.
    my $found = 0;  # Flag to indicate if a match is found.

    # Try each possible byte value.
    for my $j (0x01..0xff) {
        my $byte = pack('C', $j);  # Convert integer to byte.
        my $attempt = $file_so_far . $byte;  # Append the byte to the file content.
        my $new_hash = md5_hex($attempt);  # Compute the MD5 hash of the attempt.

        # If the hashes match, update the file content and break the loop.
        if ($new_hash eq $hash) {
            $file_so_far = $attempt;
            $found = 1;
            last;
        }
    }

    # If no matching byte is found, print an error and break the main loop.
    if (!$found) {
        print("ERROR: could not find valid byte\n");
        last;
    }

    $i += 1;  # Increment the counter.
}

# Write the recovered file content to the output file.
open my $fh, '>', $output or die "Could not open file '$output' $!";  # Open the output file.
print $fh $file_so_far;  # Write the file content.
close $fh;  # Close the file.
