"""
modify_pcap_ip.py

Description:
    A Python script that modifies the IP addresses in PCAP files using tcprewrite,
    which is part of the tcpreplay suite. Make sure tcprewrite is installed.
    
    To install tcpreplay on macOS, run:
        brew install tcpreplay

    You can verify the installation with:
        which tcprewrite

    Example tcprewrite command:
        tcprewrite --pnat=152.23.0.0/16:152.23.0.1/0 --outfile=mypackets-clean.pcap --infile=messenger53_truncated.pcap

Usage:
    python3 modify_pcap_ip.py <pcap_directory> <output_pcap_directory>

This script processes all PCAP files in the specified input directory,
modifies their IP addresses according to the provided parameters, and writes
the modified PCAP files to the output directory.
"""
import os
import sys
import ipaddress
import subprocess

def main(input_directory, output_directory):
    # starting target IP; use the given example as starting point
    target_ip = ipaddress.IPv4Address("152.23.0.1")
    source_prefix = "152.23.0.0/16"
    # list all pcap files in directory
    pcap_files = [f for f in os.listdir(input_directory) if f.endswith(".pcap")]
    pcap_files.sort()  # sort alphabetically (or randomize if desired)

    for pcap in pcap_files:
        infile = os.path.join(input_directory, pcap)
        outfile = os.path.join(output_directory, pcap.replace(".pcap", f"-ip-mod-{target_ip}.pcap"))
        # build the --pnat value with current target_ip.
        pnat_val = f"{source_prefix}:{target_ip}/0"
        cmd = [
            "tcprewrite",
            f"--pnat={pnat_val}",
            f"--infile={infile}",
            f"--outfile={outfile}"
        ]
        print("Running:", " ".join(cmd))
        ret = subprocess.run(cmd)
        if ret.returncode != 0:
            print(f"Error processing {infile}")
        # Increment target_ip by one. ipaddress takes care of rollover.
        target_ip += 1

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 merge_ip_modify.py <pcap_directory> <output_pcap_directory>")
        sys.exit(1)
    input_directory = sys.argv[1]
    if not os.path.isdir(input_directory):
        print(f"Input Directory not found: {input_directory}")
        sys.exit(1)
    output_directory = sys.argv[2]
    if not os.path.isdir(output_directory):
        print(f"Input Directory not found: {output_directory}")
        sys.exit(1)
    main(input_directory, output_directory)