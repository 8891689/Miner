Bitcoin mining software, compatible with most platforms, supports multi-threading, realizes CPU mining, can configure files by yourself, and supports most mining pools.

{
  "pool_host": "solo.ckpool.org",
  "pool_port": 3333,
  "wallet_address": "13HQ67Cqb8ZbfQThSAqX2RcXi6mhG69y39.pyworker",
  "threads": 1,
  "pool_password": "x",
  "log_file": "miner_py.log"
}

1. Pool URL
2. Pool Port
3. wallet_address
4. threads
5. pool_password Default: x
6. Miner's Diary Default: miner_py.log

In fact, you only need to replace the address in the configuration file with yours and you can run it directly.



Please fill in the information above and install the necessary dependencies to run the program.

Core Dependencies:

Python 3 Interpreter:

Introduction: This is the basis for running Python scripts. Scripts use Python 3 syntax and features (such as f-strings, int.from_bytes, etc.).

Requirements: You need to install Python 3. It is recommended to use Python 3.7 or higher to ensure that all syntax and library functions are available.

Installation command (example):

Debian/Ubuntu Linux: sudo apt update && sudo apt install python3 python3-pip

Fedora Linux: sudo dnf install python3 python3-pip

macOS: Usually the system comes with an older version, it is recommended to use Homebrew to install the latest version: brew install python

Windows: Download the installation package from the Python official website https://www.python.org/downloads/, remember to check "Add Python to PATH" when installing.

pip is the package manager for Python. Although this script currently does not require additional installation packages, installing pip is a standard practice for managing the Python environment.

Standard libraries used by the script (no additional installation required):

A great thing about this script is that it only uses Python's standard library, which means that as long as you have Python 3 installed, these libraries are already built-in, and there is no need to install any third-party packages using tools such as pip.

The following are the standard libraries it uses and their brief functions:

socket: used for network communication and establishing a connection with the mining pool.

json: used to parse and generate JSON formatted data (Stratum protocol communication).

time: used to handle time-related operations, such as delay (time.sleep), get timestamps (time.monotonic).

hashlib: used to calculate hash values ​​(such as SHA256d).

binascii: used for conversion between binary and ASCII (such as hexlify, unhexlify).

threading: used to create and manage multiple threads (miner threads, status threads, subscription threads).

logging: used to log information to the console and files.

signal: used to handle operating system signals (such as SIGINT for Ctrl+C).

sys: used to access variables and functions related to the Python interpreter (such as sys.stderr, sys.exit).

os: used to interact with the operating system (such as checking the existence of files os.path.exists, getting the terminal size os.get_terminal_size).

struct: used to handle binary data packing and unpacking (although in this version you may use int.to_bytes/from_bytes directly more).

datetime (from ... import): used to handle dates and times.

math (from ... import): for math calculations (e.g. log2, pow - though this may not be used directly in this version).

collections (from ... import): for high-level data structures (e.g. deque for storing hash counts).

select: for efficient I/O multiplexing, checking if a socket is readable/writable/exceptional (used for non-blocking reception in SubscribeThread).

Summary:

The only dependency you need to install is: Python 3 (3.7+ recommended)

Installation command: depends on your operating system (see the examples above).

No additional Python packages needed: the script does not depend on any third-party libraries that need to be installed with pip install ....

Implicit dependencies: an operating system capable of running Python 3 (Linux, macOS, Windows).

So, as long as your system has a suitable version of Python 3 installed, this script will simply run python3 miner.py (or probably python miner.py on Windows).
