# pcap_lib

A Python library to parse PCAP files, extracting packet-level information such as timestamps, IP addresses, ports, protocols, and TCP flags.

## Prerequisites

Before building and using the library, ensure that [libpcap](https://www.tcpdump.org/) is installed on your system.

### Installing libpcap

- **macOS:**  
  You can install libpcap via Homebrew:
  ```bash
  brew install libpcap
  ```

- **Ubuntu/Debian:**  
  ```bash
  sudo apt-get update
  sudo apt-get install libpcap-dev
  ```

- **Fedora/RedHat:**  
  ```bash
  sudo dnf install libpcap-devel
  ```

## Setup

Compile the C extension module in-place by running:

```bash
python3 setup.py build_ext --inplace
```

This command builds the necessary extension modules required by `pcap_lib`.

## Usage

To use the `PcapReader` to parse a PCAP file, import the class and iterate over the packets. The following example demonstrates the usage:

```python
from pcap_lib.pcap_parser import PcapReader

reader = PcapReader("merged_output_ip_mod.pcap")
for packet in reader:
    print(packet)
```

## Sample Output

The output when iterating over packets may look similar to:

```plaintext
{'timestamp': '1715193684.197687', 'src_ip': '152.23.136.63', 'dst_ip': '34.104.35.123', 'src_port': '58058', 'dst_port': '80', 'protocol': 'TCP', 'packet_length': '52', 'tcp_seq': '1570382993', 'tcp_ack': '2798950132', 'tcp_flags': 'FIN:0, SYN:0, RST:0, ACK:1'}
{'timestamp': '1715193683.394553', 'src_ip': '142.251.163.94', 'dst_ip': '152.23.136.63', 'src_port': '443', 'dst_port': '61528', 'protocol': 'UDP', 'packet_length': '52'}
```

## Repository Structure

- `setup.py`: Build script for creating the Python C extension.
- `pcap_lib/`: Contains the source for the PCAP parsing library.
  - `pcap_parser.py`: The Python module for reading and parsing PCAP files.
  - Other supporting files and modules.

## Requirements

- Python 3.x
- C compiler (e.g., gcc)
- libpcap (installed via your package manager)
