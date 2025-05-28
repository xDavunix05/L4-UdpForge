
<!-- SEO keywords: udp flood, udp flood attack, udp flood payload, udp flood script, udp flood tool, udp flood python, denial of service, dos attack, network security, udp flood detection, udp flood mitigation, udp flood example, udp flood github, udp flood, udp payload, custom-payload, amplify with payload udp, network-scanning, open source -->

## udpflood.py


## Description
udpflood.py is a Python script designed to send UDP flood packets with customizable payloads. It supports crafting payloads using both ASCII and hexadecimal formats and offers a variety of predefined payload modes, including:
- random
- ff
- icmp
- malformed
- zero
- inc

Additionally, it features an amplify mode, which supports DNS payloads only for amplification attacks.

## Features
- Flood or amplify UDP packets to one or more targets
- Supports random, zero, ff, inc, malformed, custom, and ICMP payloads
- DNS payloads available in amplify mode only
- Custom payloads via ASCII or hexadecimal input
- Network device scanning and channel hopping

## Requirements
- Python 3.x
- scapy


## Installation

1. Clone the repository:

   ```shell
   https://github.com/xDavunix05/L4-UdpForge.git
   ```

2. Navigate to the project directory:

   ```shell
   cd L4-UdpForge
   ```

3. Install the required dependencies:

   ```shell
   pip install -r requirements.txt
   ```
---

## Usage

### Basic Example
```python
python3 udpflood.py -n 192.168.1.0/24 --payload-mode ff -m flood
```

### Command Line Usage

```
udpflood.py [-h] [-m {flood,amplify,random}] [-t THREADS] [-i INTERFACE]
            [-n NETWORK] [-T TARGET] [-p PORT] [-s SIZE] [-c COUNT]
            [-v INTERVAL] [--format-ascii STRING | --format-hexa HEX]
            [--payload-mode {random,zero,ff,inc,malformed,custom,icmp}]
            [--channels CHANNELS] [--dns DNS]

UDP utils with payloads

options:
  -h, --help            show this help message and exit
  -m, --mode {flood,amplify,random}
                        Flood mode
  -t, --threads THREADS
                        Parallel process count
  -i, --interface INTERFACE
                        Network interface (unused)
  -n, --network NETWORK
                        Network/subnet to scan (e.g., 192.168.1.1/24)
  -T, --target TARGET   Specific target IP address
  -p, --port PORT       UDP port
  -s, --size SIZE       Payload size (bytes) or 'auto' for random 1-1450
  -c, --count COUNT     Packets per process (0=infinite)
  -v, --interval INTERVAL
                        Interval between packets (seconds)
  --format-ascii STRING
                        Use ASCII payload format with the given string
  --format-hexa HEX     Use hexadecimal payload format with the given hex string
  --payload-mode {random,zero,ff,inc,malformed,custom,icmp}
                        Payload pattern
  --channels CHANNELS   Comma-separated channel list for hopping (e.g., 1,6,11)
  --dns DNS             Domain for DNS query payload (amplify mode only)
```

### Notes
- **Payloads:** You must specify a payload mode (`--payload-mode`).  
- **Custom Payloads:** For custom payloads, you must provide either `--format-ascii` or `--format-hexa`.
- **DNS Payload:** The DNS payload feature is available **only** in "amplify" mode. If you specify a DNS domain with `--dns`, it will only be used when `--mode amplify` is set; other modes do not support DNS payloads.
- **Authorization:** Use this tool only on systems you own or have explicit permission to test. Unauthorized use is prohibited and may be illegal.

## Configuration
- **Custom Payloads:**  
  Use `--format-ascii` for ASCII payloads or `--format-hexa` for hexadecimal payloads with `--payload-mode custom`.
- **DNS Amplification:**  
  Use `--dns` with `-m amplify` to send DNS query payloads.

## Troubleshooting
- **Permission Errors:**  
  Raw sockets require root privileges. Run the script with `sudo` if needed.
- **Dependency Issues:**  
  Ensure `scapy` is installed:  
  ```sh
  pip install scapy
  ```
- **Invalid Arguments:**  
  Use `-h` or `--help` to see all available options.

## License
**This script is provided "as-is". Use it at your own risk. The author is not responsible for any issues that may arise from using this script.**
MIT License  
See the [LICENSE](LICENSE) file for more details.

## Author
xdavunix05

## Contact
For questions or issues, please open an issue on the GitHub repository or contact the author directly.
