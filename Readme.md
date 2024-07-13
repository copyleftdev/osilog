# osilog

`osilog` is a powerful network monitoring tool designed to capture and analyze network packets. It provides detailed insights into network activities, including TCP, UDP, ICMP, and ARP packets, with advanced logging features. Additionally, `osilog` can detect SSL/TLS handshake issues and alerts, making it an invaluable tool for network engineers and DevOps professionals.

## Features

- **Network Packet Capture**: Captures TCP, UDP, ICMP, and ARP packets.
- **TLS/SSL Detection**: Identifies and logs TLS handshake messages and alerts.
- **Structured Logging**: Uses `logrus` for color-coded and emoji-enhanced logs.
- **Log Level Filtering**: Allows filtering logs by severity (info, warn, error).

## Installation

### Prerequisites

- Go 1.18 or higher
- libpcap (required for `gopacket`)

### Build from Source

1. **Clone the repository:**

   ```sh
   git clone https://github.com/copyleftdev/osilog.git
   cd osilog
   ```

2. **Build the project:**

   ```sh
   go build -o osilog main.go
   ```

3. **Run the tool:**

   ```sh
   sudo ./osilog --interface <your-network-interface>
   ```

## Usage

### Command-line Options

- `--interface`, `-i`: Specify the network interface to capture packets from (required).
- `--loglevels`, `-l`: Set log levels to filter output (default: `info`). Possible values: `info`, `warn`, `error`.

### Examples

- **Capture packets on interface `enp0s3` and show all log levels:**

  ```sh
  sudo ./osilog --interface enp0s3
  ```

- **Capture packets on interface `enp0s3` and filter logs to show warnings and errors only:**

  ```sh
  sudo ./osilog --loglevels warn,error --interface enp0s3
  ```

## Log Output

The tool uses `logrus` for structured logging with color coding and emojis for better readability. Here are some examples of the log output:

- **Info**:

  ```
  [2024-07-12T20:06:17-07:00] INFO  📦 Packet captured timestamp=2024-07-12T20:06:17-07:00 length=123
  ```

- **Warning**:

  ```
  [2024-07-12T20:06:17-07:00] WARN  🚨 TCP Reset (RST) detected src_ip=192.168.0.35 src_port=55092 dst_ip=172.64.155.141 dst_port=443
  ```

- **Error**:

  ```
  [2024-07-12T20:06:17-07:00] ERROR 🔒 TLS alert message detected src_ip=192.168.0.35 dst_ip=172.64.155.141
  ```

## Internals

### Project Structure

- **`main.go`**: Entry point of the application.
- **`cmd/`**: Contains CLI command definitions.
- **`capture/`**: Handles packet capturing and processing.
- **`logger/`**: Configures and manages logging.
- **`tls/`**: Contains logic for inspecting and detecting TLS-related issues.

### Code Highlights

#### Command Handling (`cmd/root.go`)

Defines the root command and initializes the required flags for network interface and log levels.

#### Packet Capture (`capture/capture.go`)

Handles the core packet capturing logic using `gopacket` and processes each packet to detect network issues.

#### Logging Configuration (`logger/logger.go`)

Configures `logrus` for structured logging with different log levels and color-coded output.

#### TLS Issue Detection (`tls/tls.go`)

Inspects TCP payloads for TLS handshake messages and alerts, logging them as appropriate.

## Contribution

We welcome contributions from the community! Feel free to fork the repository and create pull requests. Here are some areas where you can contribute:

- Adding new features
- Improving existing functionalities
- Bug fixes
- Documentation improvements
