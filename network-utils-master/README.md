# Network Utils Suite

This repository provides a collection of utilities for processing PCAP files and network flows. They include C programs for parsing and analyzing PCAP files, as well as Python scripts for modifying PCAP IP addresses and processing flow records over ZeroMQ.

## Repository Structure

### C Programs

- **[pcap_parser.c](pcap_parser.c)**  
  A simple PCAP parser that reads packets, extracts TCP/UDP headers (including timestamps, IP addresses, ports, and protocols), and prints packet details.  
  **Compile:**  
  ```sh
  gcc -Wall -Wextra -o pcap_parser pcap_parser.c -lpcap
  ```  
  **Run:**  
  ```sh
  ./pcap_parser <pcap_file>
  ```

- **[merge_pcap.c](merge_pcap.c)**  
  Merges many PCAP files into one output file by simulating multiple concurrent sessions/users.  
  **Compile:**  
  ```sh
  gcc -O2 -Wall -o merge_pcap merge_pcap.c -lpcap
  ```  
  **Run:**  
  ```sh
  ./merge_pcap <pcap_directory> <N_sessions> <output.pcap>
  ```

- **[flowhash.c](flowhash.c)**  
  Tracks the first 40 packets of every bidirectional flow (using a five-tuple key) and dumps the flow record when complete.  
  **Compile:**  
  ```sh
  gcc -O3 -std=c11 -Wall flowhash.c -o flowhash -lpcap
  ```  
  **Run:**  
  ```sh
  ./flowhash <pcap_file>
  ```

- **[flowhash_timing_wheel.c](flowhash_timing_wheel.c)**  
  Similar to flowhash.c but uses a timing-wheel for efficient UDP idle detection.  
  **Compile:**  
  ```sh
  gcc -o flowhash_timing_wheel flowhash_timing_wheel.c -lpcap
  ```  
  **Run:**  
  ```sh
  ./flowhash_timing_wheel <pcap_file>
  ```

- **[flowhash_zmq.c](flowhash_zmq.c)**  
  Tracks flows and, when a flow finishes, sends the flow record as a JSON object over ZeroMQ.  
  **Compile:**  
  ```sh
  gcc flowhash_zmq.c -std=c11 -Wall -O2 -lpcap $(pkg-config --cflags --libs jansson libzmq) -pthread -o flowhash_zmq
  ```  
  **Run:**  
  ```sh
  ./flowhash_zmq <pcap_file>
  ```
- **[flowhash_zmq_timing_wheel.c](flowhash_zmq_timing_wheel.c)**  
  Tracks flows and, when a flow finishes, sends the flow record as a JSON object over ZeroMQ. It uses the timing wheel to evict flows.  
  **Compile:**  
  ```sh
  gcc flowhash_zmq_timing_wheel.c -std=c11 -Wall -O2 -lpcap $(pkg-config --cflags --libs jansson libzmq) -pthread -o flowhash_zmq_timing_wheel
  ```  
  **Run:**  
  ```sh
  ./flowhash_zmq_timing_wheel <pcap_file>
  ```

### Python Scripts

- **[modify_pcap_ip.py](modify_pcap_ip.py)**  
  Modifies the IP addresses in PCAP files using tcprewrite (from the tcpreplay suite).  
  **Run:**  
  ```sh
  python3 modify_pcap_ip.py <pcap_directory> <output_pcap_directory>
  ```

- **[zmq_pcap_multiworker.py](zmq_pcap_multiworker.py)**  
  Runs one or more ZeroMQ PULL workers to receive and process flow records concurrently.  
  **Usage:**  
  ```sh
  python3 zmq_pcap_multiworker.py [--endpoint <endpoint>] [--output <output_file>] [--num-workers <N>]
  ```

- **[zmq_pcap_worker.py](zmq_pcap_worker.py)**  
  A ZeroMQ worker that receives flow records and optionally performs additional processing (such as classification).  
  **Usage:**  
  ```sh
  python3 zmq_pcap_worker.py [--endpoint <endpoint>] [--output <output_file>]
  ```

### Python Library (pcap_lib/)

This folder contains a Python C extension to parse PCAP files.

- **[pcap_parser_final.c](pcap_lib/src/pcap_parser_final.c)**  
  Implements a Python iterator over packets in a PCAP file, providing packet-level details.  
- **[setup.py](pcap_lib/setup.py)**  
  Build script for compiling the C extension module.

  **Build the module:**  
  ```sh
  python3 setup.py build_ext --inplace
  ```

  **Usage Example:**  
  ```python
  from pcap_lib.pcap_parser import PcapReader

  reader = PcapReader("your_pcap_file.pcap")
  for packet in reader:
      print(packet)
  ```

### Miscellaneous

## Prerequisites

- **For C Programs:**  
  - GCC and a C compiler  
  - libpcap  
  - Additionally, for `flowhash_zmq.c`, install ZeroMQ and Jansson (for JSON):  
    - On macOS:  
      ```sh
      brew install libpcap zeromq jansson
      ```  
    - On Ubuntu/Debian:  
      ```sh
      sudo apt-get update
      sudo apt-get install libpcap-dev libzmq3-dev libjansson-dev
      ```

- **For Python Scripts/Library:**  
  - Python 3  
  - tcprewrite (from the tcpreplay suite) for `modify_pcap_ip.py`  
  - For machine learning functionalities in `zmq_pcap_worker.py`, required packages include TensorFlow, Keras, scikit-learn, numpy, etc.

## Summary

This suite of tools serves multiple purposes:
- **PCAP Parsing:** Extract packet details and flow information from PCAP files.
- **Flow Tracking:** Monitor network flows using hash-based methods including timing wheels and ZeroMQ for distributed processing.
- **PCAP Modification:** Modify IP addresses in PCAP files using tcprewrite.
- **Python Integration:** Use the provided C extension module to iterate over PCAP packets from Python.

