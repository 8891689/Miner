# Miner

This is a basic, multi-threaded CPU miner written in C++ for the SHA256d algorithm (used by Bitcoin and others). It connects to mining pools using the Stratum v1 protocol.

The python version does not require any dependencies, and you can mine by simply filling in the wallet address in the configuration file, but it is 4 times slower than C++.

## Features

*   CPU mining using the SHA256d algorithm.
*   Supports the Stratum v1 mining protocol.
*   Multi-threaded to utilize multiple CPU cores.
*   Optimized SHA256 hashing using SSE2 and SSSE3 instruction sets.
*   Configuration via a `config.json` file.
*   Automatic reconnection on pool connection loss.
*   Periodic status display (hashrate, pool difficulty, block height, etc.).
*   Cross-platform support (Linux, macOS, Windows with MinGW).
*   Uses the GMP library for arbitrary-precision arithmetic (for target difficulty calculations).

## Requirements

*   A C++11 compliant compiler (e.g., g++).
*   CPU with **SSE2** and **SSSE3** instruction set support (the miner checks this at startup).
*   Required dependencies (and their development packages/headers):
    *   `libcurl` (for fetching initial block height via API)
    *   `libjson-c` (for parsing Stratum protocol JSON messages)
    *   `libgmp` (for large number arithmetic)
    *   `pthreads` (threading library - usually built-in on Linux/macOS, may require setup with MinGW)
    *   `(Windows only)` `ws2_32` (Winsock library - typically included with MinGW)

## Dependencies Installation

Before compiling, ensure you have installed the necessary dependencies. Here are commands for common systems:

**Debian / Ubuntu:**

```bash
sudo apt update
sudo apt install build-essential g++ libcurl4-openssl-dev libjson-c-dev libgmp-dev
```

(build-essential usually includes g++ and make)

Fedora / CentOS / RHEL (using dnf or yum):

# Fedora or newer RHEL/CentOS (using dnf)
```
sudo dnf install gcc-c++ make libcurl-devel json-c-devel gmp-devel
```
# Older RHEL/CentOS (using yum)
```
sudo yum groupinstall "Development Tools" 
```
# May be needed if gcc-c++ and make aren't installed
```
sudo yum install libcurl-devel json-c-devel gmp-devel
```

# macOS (using Homebrew):

First, ensure you have Xcode Command Line Tools installed:
```
xcode-select --install
```
Then, install dependencies using Homebrew:
```
brew install curl json-c gmp
```

(macOS usually includes curl, but brew install curl ensures headers/libs are easily found by the linker)

# Windows (using MinGW-w64 / MSYS2):

If you are using the MSYS2 environment with a MinGW-w64 toolchain, you can install dependencies using pacman:

Run these in the MSYS2 MinGW 64-bit terminal
```
pacman -Syu
pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-curl mingw-w64-x86_64-json-c mingw-w64-x86_64-gmp
```

(Note: pthreads is typically included in the MinGW toolchain, and ws2_32 is a Windows system library)

# Compilation

After installing the dependencies, compile the miner:

# Linux / macOS:
```
g++ miner.cpp sha256.cpp sha256_sse.cpp -o miner -O3 -march=native -lcurl -ljson-c -pthread -lm -lgmp

```

# Windows (using MinGW-w64):
```
g++ miner.cpp sha256.cpp sha256_sse.cpp -o miner.exe -O3 -march=native -lcurl -ljson-c -lpthread -lm -lgmp -lws2_32

```
```
-std=c++11: Specifies the C++ standard.

-march=native： General detection CPU instruction optimization compilation

-O3: Enable level 3 optimizations. Unsupported computers will automatically downgrade to O2 Normal Optimization.

-msse2 -mssse3: Enable the required CPU instruction sets.

-l...: Links the necessary libraries.
```
# Configuration

The miner requires a configuration file named config.json in the same directory as the executable. If the file doesn't exist, the miner will attempt to create an example file.

# Example config.json:
```
{
  "pool_host": "solo.ckpool.org",
  "pool_port": 3333,
  "wallet_address": "13HQ67Cqb8ZbfQThSAqX2RcXi6mhG69y39.pyworker",
  "threads": 1,
  "pool_password": "x",
  "log_file": "miner.log"
}
```

# Field Descriptions:

pool_host: (Required) The Stratum server address of your mining pool.

pool_port: (Required) The Stratum port number for your mining pool.

wallet_address: (required) Key: Change this to your own wallet address (or wallet_address.worker_name format, usually fill in the address directly without the miner name, it depends on you and the pool).

threads: (Required) The number of CPU mining threads to use. Setting this to the number of your CPU's physical cores or logical threads is recommended.

pool_password: (Optional) The password for your worker on the pool. Often set to "x" or can be left empty, depending on the pool's requirements. Defaults to "x".

log_file: (Optional) The name of the file where logs will be written. Defaults to "miner.log".

# Usage

Install Dependencies (see "Dependencies Installation" section above).

Compile the miner (see "Compilation" section above).

Create and edit the config.json file in the same directory as the compiled executable, filling in your pool and wallet details.

# Run the miner:

On Linux/macOS: ./miner

On Windows: miner.exe

The program will connect to the specified pool, retrieve mining jobs, and start hashing using the configured number of threads. Status information will be displayed periodically in the terminal, and detailed logs will be written to the configured log file.

Press Ctrl+C to stop the miner gracefully.


# Thanks: gemini, ChatGPT

# Sponsorship
If this project has been helpful to you, please consider buying me a coffee. Your support is greatly appreciated. Thank you!
```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
Dogecoin: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
```
# 📜 Disclaimer
Mining with CPUs (e.g. Bitcoin) is generally not very profitable due to the high network hashrate being dominated by ASIC miners. This software is primarily intended for educational purposes, testing, or mining coins with very low network difficulty.

