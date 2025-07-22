ECE TUC / 2024-25 / Group 6
# TCP SpeedTest with Unix Sockets – README

## Overview

This project implements a simple **TCP-based throughput measurement tool** in C, consisting of two programs:

- `server.c`: Accepts TCP connections and calculates per-interval and average throughput over a fixed duration.
- `client.c`: Connects to the server and sends dummy data continuously at maximum speed.

The system is designed to simulate a real-world speed test between a client and an access point/server, and to allow **precise throughput logging every 2 seconds**, as required for network performance analysis.

---

## Server (`server.c`)

The server is responsible for receiving traffic from a single client connection and calculating throughput statistics.

### Key functions:

- **`server_setup()`**  
  Creates a TCP socket bound to port `14444`, with `SO_REUSEADDR` enabled and a backlog of 1 connection. This ensures only one client is handled at a time.

- **`get_real_time()`**  
  Utility function that returns the current time with microsecond precision using `gettimeofday()`.

- **`handle_client()`**  
  Core logic that:
    - Receives incoming data for 30 seconds using `recv()`
    - Calculates throughput every 2 seconds based on the number of received bytes
    - Prints per-interval and average throughput in Mbps using:
      \[
      \text{Throughput (Mbps)} = \frac{\text{bytes\_received} \times 8}{10^6 \times \text{interval}}
      \]

- **`main()`**  
  Initializes the server and waits for incoming connections. After each connection:
    - Handles the test via `handle_client()`
    - Closes the client socket
    - Waits for the next client

---

## Client (`client.c`)

The client sends continuous traffic to the server and logs the sending throughput over the course of 30 seconds.

### Key steps:

- Resolves the server address using `getaddrinfo()`
- Establishes a TCP connection via `socket()` and `connect()`
- Prepares a 64KB buffer of dummy data (`'A'`) for transmission
- Sends data continuously using `send()`
- Measures the number of bytes sent every 2 seconds and calculates the sending throughput
- Reports:
    - Instantaneous throughput every 2 seconds
    - Total throughput after 30 seconds

---

## Constants

| Constant       | Value   | Purpose                             |
|----------------|---------|-------------------------------------|
| `PORT`         | 14444   | TCP port used by the server         |
| `BUFSIZE`      | 65536   | Size of data buffer (64KB)          |
| `INTERVAL`     | 2       | Reporting interval in seconds       |
| `DURATION`     | 30      | Duration of the speed test in sec   |
| `TCP_BACKLOG`  | 1       | Max number of simultaneous clients  |

---

## Usage

### 1. Compile

Run "make" or "make all" in terminal, and it will be done automatically. Alternatively, do it yourself:

```bash
gcc -o server server.c
gcc -o client client.c
```


### 2. Run the server 
Will keep the server open and listening for any potential connection.

```bash
./server
```

### 3.Run the client
The IP of the server needs to be provided when running the client.

```bash
./client <server-ip-address>
```