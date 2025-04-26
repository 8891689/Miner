#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author：8891689
# Assist in creation：gemini
import socket
import json
import time
import threading
import signal
import sys
import os
import struct
import hashlib
import binascii
import logging
import math
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
try:
    import requests
except ImportError:
    print("Error: 'requests' library not found. Please install it using: pip install requests")
    sys.exit(1)

# --- Configuration Variables ---
# Loaded from config.json
g_pool_host = ""
g_pool_port = 0
g_wallet_addr = ""
g_pool_password = "x"
g_log_file = "miner.log"
g_threads = 0

CONFIG_FILE = "config.json"
RECONNECT_DELAY_SECONDS = 5
STATUS_LOG_INTERVAL_SECONDS = 30

# ANSI colors
C_RED = "\x1b[31m"
C_GREEN = "\x1b[32m"
C_YELLOW = "\x1b[33m"
C_MAG = "\x1b[35m"
C_CYAN = "\x1b[36m"
C_RESET = "\x1b[0m"

# --- Global State ---
g_shutdown_event = threading.Event() # Replaces g_sigint_shutdown
g_connection_lost_event = threading.Event() # Replaces g_connection_lost

g_job_lock = threading.Lock() # Protects job data AND nbits/extranonce size
g_new_job_condition = threading.Condition(g_job_lock) # Replaces g_new_job_cv
g_new_job_available = False # Read/Written under g_job_lock

g_socket = None # Holds the current socket object
g_socket_lock = threading.Lock() # Protect access to g_socket

# Hashrate Calculation State
g_thread_hash_counts = [] # List of hash counts per thread (integers)
g_thread_hash_counts_lock = threading.Lock() # Protect the list structure if resizing
g_total_hashes_reported = 0
g_aggregated_hash_rate = 0.0
g_last_aggregated_report_time = time.monotonic()

# --- Stratum Job Data (Protected by g_job_lock) ---
g_job_id = None
g_prevhash_bin = b''  # Little Endian binary
g_coinb1_bin = b''
g_coinb2_bin = b''
g_merkle_branch_bin_be = []  # List of Big Endian binary bytes
g_version_le = 0  # Little Endian host format integer
g_nbits_le = 0  # Little Endian host format integer (NETWORK nBits)
g_ntime_le = 0  # Little Endian host format integer
g_clean_jobs = False

# --- Stratum Subscribe Data (Protected by g_job_lock) ---
g_extranonce1_bin = b''
g_extranonce2_size = 4  # Default, updated by subscribe response

# --- Other Globals ---
g_current_height = -1 # Block height, updated from API or job
g_current_height_lock = threading.Lock()

# Store 256-bit share target as Python int (Protected by g_share_target_lock)
# Difficulty 1 target (0x00000000FFFF0000000000000000000000000000000000000000000000000000)
TARGET1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
MAX_TARGET_256 = (1 << 256) - 1
g_share_target = TARGET1
g_share_target_lock = threading.Lock()

# --- Logger Setup ---
# Setup logging (before first log message)
log_formatter = logging.Formatter('[%(asctime)s.%(msecs)03d] [%(threadName)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Prevent duplicate handlers if script is re-run in same process
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# File Handler (configured later once g_log_file is known)
file_handler = None

# Console Handler for stderr (for specific messages like status)
# We will print directly to stderr/stdout for status/shares to match C++ style
# console_handler = logging.StreamHandler(sys.stderr)
# console_handler.setFormatter(log_formatter)
# console_handler.setLevel(logging.INFO) # Or DEBUG
# logger.addHandler(console_handler)

# --- Helper Functions ---

def setup_file_logger():
    """Sets up the file logger after config is loaded."""
    global file_handler
    if file_handler:
        logger.removeHandler(file_handler)
    try:
        file_handler = logging.FileHandler(g_log_file, mode='a') # Append mode
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.INFO) # Log INFO and above to file
        logger.addHandler(file_handler)
        #logger.info(f"File logger initialized for '{g_log_file}'")
    except Exception as e:
        print(f"{C_RED}[!!! LOG FILE SETUP ERROR !!!] Cannot write to '{g_log_file}': {e}{C_RESET}", file=sys.stderr)
        # Continue without file logging

def log_msg(level, message):
    """Logs message to file logger."""
    # Map level for logging module if needed, or just use info/warning/error
    if level == logging.INFO:
        logger.info(message)
    elif level == logging.WARNING:
        logger.warning(message)
    elif level == logging.ERROR:
        logger.error(message)
    elif level == logging.DEBUG:
        logger.debug(message)
    else: # Default to info
        logger.info(message)

def timestamp_us():
    """Gets timestamp string with microseconds, matching C++ format."""
    now = datetime.now()
    return now.strftime('%H:%M:%S.%f')[:15] # Format H:M:S.us (6 digits)

def bin_to_hex(binary_data):
    """Converts bytes to hex string."""
    return binascii.hexlify(binary_data).decode('ascii') if binary_data else ""

def hex_to_bin(hex_string):
    """Converts hex string to bytes. Returns None on error."""
    if not hex_string or len(hex_string) % 2 != 0:
        return None
    try:
        return binascii.unhexlify(hex_string)
    except (binascii.Error, ValueError, TypeError):
        # log_msg(logging.ERROR, f"[UTIL] hex_to_bin failed for input: {hex_string[:50]}...") # Avoid logging potentially huge strings
        return None

def sha256_double_be(data_bytes):
    """Performs double SHA256 and returns the result as big-endian bytes."""
    first_hash = hashlib.sha256(data_bytes).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    return second_hash # SHA256 result is naturally big-endian

def calculate_simplified_merkle_root_le(
    coinb1_bin_param, extranonce1_bin_param,
    extranonce2_bin_param, coinb2_bin_param,
    merkle_branch_be_list_param):
    """Calculates the Merkle Root and returns it as Little Endian bytes."""
    # Construct full coinbase transaction binary
    coinbase_tx_bin = (
        coinb1_bin_param +
        extranonce1_bin_param +
        extranonce2_bin_param +
        coinb2_bin_param
    )

    # Double SHA256 the coinbase transaction -> Coinbase Hash (Big Endian)
    current_hash_be = sha256_double_be(coinbase_tx_bin)

    # Combine with merkle branches (provided in Big Endian)
    for branch_hash_be in merkle_branch_be_list_param:
        concat_be = current_hash_be + branch_hash_be
        current_hash_be = sha256_double_be(concat_be) # New current hash (BE)

    # Final result (current_hash_be) is the Merkle Root in Big Endian.
    # Return it in Little Endian as needed for the block header.
    merkle_root_le = current_hash_be[::-1] # Reverse bytes for LE
    return merkle_root_le

def is_hash_less_or_equal_target(hash_le_bytes, target_int):
    """Checks if a 32-byte LE hash is <= the integer target."""
    if not hash_le_bytes or len(hash_le_bytes) != 32:
        return False
    hash_int = int.from_bytes(hash_le_bytes, 'little')
    return hash_int <= target_int

# Difficulty calculation using nBits (from C++ logic)
def calculate_difficulty_nbits(nbits_le_int):
    """Calculates difficulty from nBits (Little Endian integer)."""
    if nbits_le_int == 0: return 0.0
    # Convert nBits (LE int) to BE bytes for easier parsing
    try:
        nbits_be_bytes = struct.pack('>I', nbits_le_int) # Pack as BE int
        nbits_be_parsed = struct.unpack('>I', nbits_be_bytes)[0] # Unpack to ensure correct handling
    except struct.error:
        return 0.0 # Invalid nbits value

    exponent = (nbits_be_parsed >> 24) & 0xFF
    coefficient = nbits_be_parsed & 0x00FFFFFF

    if coefficient == 0: return float('inf')
    if exponent < 3 or exponent > 32: return 0.0 # Invalid exponent

    # Difficulty 1 target (0x1d00ffff) values -> Target1 int already defined
    # target = coefficient * 2^(8*(exponent-3))
    # difficulty = TARGET1 / target
    try:
        target = coefficient * (2**(8 * (exponent - 3)))
        if target == 0: return float('inf')
        # Use floating point for potentially large division result
        difficulty = float(TARGET1) / float(target)
        return difficulty
    except OverflowError:
        # Calculation might exceed standard float limits, use simplified ratio
        try:
             diff1_coeff = 0x00ffff
             diff1_exp = 0x1d # 29
             diff1_exp_shift = 8 * (diff1_exp - 3)
             current_exp_shift = 8 * (exponent - 3)
             difficulty = (float(diff1_coeff) / float(coefficient)) * math.pow(2.0, diff1_exp_shift - current_exp_shift)
             return difficulty
        except (OverflowError, ValueError):
             return float('inf') # Or some other indicator of extreme difficulty
    except Exception:
        return 0.0 # Other errors

# Calculate difficulty from a 256-bit target integer
def calculate_difficulty_from_target(target_int):
    """Calculates difficulty from a 256-bit integer target."""
    if target_int <= 0:
        # Target is zero or negative, difficulty is effectively infinite
        log_msg(logging.WARNING, "[UTIL] calculate_difficulty_from_target: Target is non-positive.")
        return float('inf')
    try:
        # Difficulty = target1 / target_current
        # Use floating point for potentially large/small ratios
        difficulty = float(TARGET1) / float(target_int)
        return difficulty
    except OverflowError:
        return float('inf') # Target extremely small
    except Exception as e:
        log_msg(logging.ERROR, f"[UTIL] Exception during difficulty calculation from target: {e}")
        return 0.0 # Indicate error

def uint32_to_hex_be(val_le_int):
    """Convert uint32_t (Little Endian host int) to Big Endian hex string."""
    try:
        # Pack as little-endian, unpack as big-endian, then format
        be_int = struct.unpack('>I', struct.pack('<I', val_le_int))[0]
        return f"{be_int:08x}"
    except struct.error:
        return "00000000" # Error case

def increment_extranonce2(enonce2_bytearray):
    """Increments the extranonce2 bytearray (Little Endian)."""
    if not enonce2_bytearray:
        return False # Nothing to increment

    size = len(enonce2_bytearray)
    for i in range(size):
        if enonce2_bytearray[i] == 0xff:
            enonce2_bytearray[i] = 0
            # Continue to carry to the next byte
        else:
            enonce2_bytearray[i] += 1
            return True # Increment successful without full wrap

    # If we exit the loop, all bytes wrapped around
    return False # Indicates full wrap around

# --- Config Loading ---
def load_config():
    global g_pool_host, g_pool_port, g_wallet_addr, g_threads
    global g_pool_password, g_log_file

    try:
        with open(CONFIG_FILE, 'r') as f:
            config_content = f.read()
    except FileNotFoundError:
        print(f"{C_RED}[ERROR] Config file '{CONFIG_FILE}' not found.{C_RESET}", file=sys.stderr)
        # Create example config
        try:
            with open(CONFIG_FILE, 'w') as f_example:
                example_json = {
                    "pool_host": "stratum.example.com",
                    "pool_port": 3333,
                    "wallet_address": "YOUR_BTC_WALLET_ADDRESS",
                    "threads": 4,
                    "pool_password": "x",
                    "log_file": "miner.log"
                }
                json.dump(example_json, f_example, indent=2)
            print(f"[INFO] Created example config file '{CONFIG_FILE}'. Please edit it with your details.", file=sys.stderr)
        except Exception as e:
            print(f"{C_RED}[ERROR] Could not create example config file '{CONFIG_FILE}': {e}{C_RESET}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"{C_RED}[ERROR] Failed to read config file '{CONFIG_FILE}': {e}{C_RESET}", file=sys.stderr)
        return False

    if not config_content:
        print(f"{C_RED}[ERROR] Config file '{CONFIG_FILE}' is empty.{C_RESET}", file=sys.stderr)
        return False

    try:
        config = json.loads(config_content)
    except json.JSONDecodeError as e:
        print(f"{C_RED}[ERROR] Failed to parse JSON from config file '{CONFIG_FILE}'. Check syntax: {e}{C_RESET}", file=sys.stderr)
        return False

    # Validate and load settings
    error_field = ""
    try:
        g_pool_host = config.get("pool_host")
        if not isinstance(g_pool_host, str) or not g_pool_host:
            error_field = "pool_host (must be a non-empty string)"
            raise ValueError()

        g_pool_port = config.get("pool_port")
        if not isinstance(g_pool_port, int) or not (0 < g_pool_port <= 65535):
            error_field = "pool_port (must be an integer between 1 and 65535)"
            raise ValueError()

        g_wallet_addr = config.get("wallet_address")
        if not isinstance(g_wallet_addr, str) or not g_wallet_addr or g_wallet_addr == "YOUR_BTC_WALLET_ADDRESS":
            error_field = "wallet_address (must be a non-empty string, not the example)"
            raise ValueError()

        g_threads = config.get("threads")
        if not isinstance(g_threads, int) or g_threads <= 0:
            error_field = "threads (must be a positive integer)"
            raise ValueError()

        # Optional fields
        g_pool_password = config.get("pool_password", "x") # Default "x"
        if not isinstance(g_pool_password, str):
            error_field = "pool_password (must be a string if provided)"
            raise ValueError()

        g_log_file = config.get("log_file", "miner.log") # Default "miner.log"
        if not isinstance(g_log_file, str) or not g_log_file:
            g_log_file = "miner.log" # Force default if empty string given

    except ValueError:
        print(f"{C_RED}[ERROR] Invalid or missing configuration in '{CONFIG_FILE}': Check field '{error_field}'.{C_RESET}", file=sys.stderr)
        return False
    except Exception as e:
         print(f"{C_RED}[ERROR] Unexpected error loading config: {e}{C_RESET}", file=sys.stderr)
         return False

    print(f"[CONFIG] Configuration successfully loaded and validated from {CONFIG_FILE}")
    return True

# --- Signal Handler ---
def handle_sigint(sig, frame):
    if g_shutdown_event.is_set():
        return # Already shutting down
    print(f"\r{' '*80}\r{C_YELLOW}[SIGNAL] Shutdown initiated by SIGINT...{C_RESET}", file=sys.stderr)
    sys.stderr.flush()
    log_msg(logging.INFO,"[SIGNAL] SIGINT received, initiating shutdown...")
    g_shutdown_event.set()
    # Signal connection loss as well to break loops
    g_connection_lost_event.set()
    # Wake up any waiting threads
    with g_job_lock:
        g_new_job_condition.notify_all()

# --- Networking & Pool Communication ---

# Get current block height from an external API
def get_current_block_height():
    # Using mempool.space API as an example
    url = "https://mempool.space/api/blocks/tip/height"
    headers = {'User-Agent': 'SimplePythonMiner/1.0'}
    try:
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        height = int(response.text)
        return height
    except requests.exceptions.RequestException as e:
        log_msg(logging.ERROR, f"[HTTP] Failed to get block height from {url}: {e}")
    except (ValueError, TypeError) as e:
         log_msg(logging.ERROR, f"[HTTP] Failed to parse height response '{response.text[:100]}': {e}")
    except Exception as e:
         log_msg(logging.ERROR, f"[HTTP] Unknown error getting block height: {e}")
    return -1

# Connect to the mining pool
def connect_pool():
    """Tries to connect to the pool. Returns socket object or None."""
    log_msg(logging.INFO, f"[NET] Resolving {g_pool_host}:{g_pool_port}...")
    sock = None
    try:
        # getaddrinfo handles IPv4/IPv6 resolution
        addr_info_list = socket.getaddrinfo(g_pool_host, g_pool_port, socket.AF_UNSPEC, socket.SOCK_STREAM)

        if not addr_info_list:
             log_msg(logging.ERROR, f"[ERROR][NET] getaddrinfo failed for {g_pool_host} (no results)")
             return None

        for res in addr_info_list:
            af, socktype, proto, canonname, sa = res
            try:
                log_msg(logging.INFO, f"[NET] Attempting connect to {g_pool_host} ({sa[0]}) port {sa[1]}...")
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(10) # 10 second connection timeout
                sock.connect(sa)
                sock.settimeout(None) # Set back to blocking for normal operation
                log_msg(logging.INFO, f"[NET] Successfully connected to {g_pool_host}:{g_pool_port} via {sa[0]}")
                return sock # Return the connected socket

            except socket.error as e:
                log_msg(logging.WARNING, f"[WARN][NET] connect() to {sa[0]} failed: {e}")
                if sock:
                    sock.close()
                sock = None
                continue # Try next address
            except Exception as e:
                log_msg(logging.ERROR, f"[ERROR][NET] Unexpected error during connect attempt: {e}")
                if sock:
                    sock.close()
                sock = None
                continue

        # If loop completes without returning a socket
        log_msg(logging.ERROR, f"[ERROR][NET] Failed to connect to any resolved address for {g_pool_host}:{g_pool_port}")
        return None

    except socket.gaierror as e:
        log_msg(logging.ERROR, f"[ERROR][NET] getaddrinfo failed for {g_pool_host}: {e}")
        return None
    except Exception as e:
        log_msg(logging.ERROR, f"[ERROR][NET] Unexpected error during connection setup: {e}")
        return None

# Send JSON string over socket
def send_json_message(sock, message_dict):
    """Sends a JSON message dictionary over the socket."""
    if not sock:
        log_msg(logging.ERROR, "[ERROR][NET] send_json attempted on None socket.")
        return False
    try:
        msg = json.dumps(message_dict) + '\n'
        sock.sendall(msg.encode('utf-8')) # sendall handles partial sends
        # log_msg(logging.DEBUG, f"[DEBUG][NET] Sent: {msg.strip()}") # Optional debug log
        return True
    except socket.error as e:
        log_msg(logging.ERROR, f"[ERROR][NET] sendall() failed on socket: {e}")
        g_connection_lost_event.set() # Signal connection loss
        with g_job_lock:
            g_new_job_condition.notify_all()
        return False
    except (TypeError, json.JSONDecodeError) as e:
         log_msg(logging.ERROR, f"[ERROR][NET] Failed to encode JSON for sending: {e} - Data: {message_dict}")
         return False
    except Exception as e:
        log_msg(logging.ERROR, f"[ERROR][NET] Unexpected error sending JSON: {e}")
        g_connection_lost_event.set()
        with g_job_lock:
            g_new_job_condition.notify_all()
        return False


# --- Miner Thread ---
def miner_func(thread_id, num_threads):
    """Main function for each miner thread."""
    global g_new_job_available

    thread_name = f"Miner-{thread_id}"
    threading.current_thread().name = thread_name
    log_msg(logging.INFO, f"[MINER {thread_id}] Thread started.")

    # Thread-local state variables
    current_job_id_local = None
    extranonce2_size_local = 4
    extranonce2_bin_local = bytearray() # Use bytearray for mutability

    # Local copy of share target
    local_share_target = 0 # Initialize to 0
    share_target_loaded = False

    # Initialize hash counter for this thread
    with g_thread_hash_counts_lock:
        if thread_id >= len(g_thread_hash_counts):
             log_msg(logging.ERROR, f"[MINER {thread_id}] Error: thread_id out of range for hash counts.")
             return
        g_thread_hash_counts[thread_id] = 0 # Initialize count


    try: # Main try block for the thread function
        while not g_shutdown_event.is_set():
            need_new_job = False
            clean_job_flag = False

            # --- Declare local job variables needed for hashing ---
            version_local_le = 0
            prevhash_local_bin_le = b''
            coinb1_local_bin = b''
            coinb2_local_bin = b''
            extranonce1_local_bin = b''
            merkle_branch_local_bin_be = []
            ntime_local_le = 0
            nbits_local_le = 0
            job_id_for_new_work = None

            # --- Wait for a new job or shutdown ---
            with g_job_lock:
                # Wait until: shutdown OR connection lost OR (new job available AND its ID is different from ours)
                while not (g_shutdown_event.is_set() or g_connection_lost_event.is_set() or \
                           (g_new_job_available and g_job_id != current_job_id_local)):
                    g_new_job_condition.wait(timeout=1.0) # Wait with timeout

                # --- Check conditions after waking up ---
                if g_shutdown_event.is_set() or g_connection_lost_event.is_set():
                    break # Exit the main while loop immediately

                # Re-verify condition AFTER acquiring lock and waking up
                if g_new_job_available and g_job_id != current_job_id_local:
                    # Passed checks, it's a genuinely new job we should process
                    job_id_for_new_work = g_job_id # Remember the job ID we decided to work on
                    need_new_job = True
                    clean_job_flag = g_clean_jobs

                    # Copy necessary job details from global variables to local scope variables
                    version_local_le = g_version_le
                    prevhash_local_bin_le = g_prevhash_bin
                    coinb1_local_bin = g_coinb1_bin
                    coinb2_local_bin = g_coinb2_bin
                    extranonce1_local_bin = g_extranonce1_bin
                    merkle_branch_local_bin_be = list(g_merkle_branch_bin_be) # Copy list
                    ntime_local_le = g_ntime_le
                    nbits_local_le = g_nbits_le
                    extranonce2_size_local = g_extranonce2_size

                    # Copy the current global share target atomically
                    with g_share_target_lock:
                        if g_share_target > 0:
                            local_share_target = g_share_target
                            share_target_loaded = True
                        else:
                            share_target_loaded = False
                            log_msg(logging.WARNING, f"[WARN][MINER {thread_id}] Global share target is zero when trying to start job {g_job_id}. Waiting for target.")
                            need_new_job = False # Prevent processing this job iteration

                    # If target was loaded successfully, commit to this job
                    if need_new_job:
                        current_job_id_local = job_id_for_new_work # <<< IMPORTANT: Update local ID *inside the lock*
                        g_new_job_available = False # This thread took the job signal (or one of them)

                        # Initialize extranonce2 for the new job based on thread ID
                        extranonce2_bin_local = bytearray(extranonce2_size_local)
                        if extranonce2_size_local > 0 and num_threads > 0:
                            # Distribute starting point based on thread_id
                            # Use simple starting offset logic from C++
                            start_val = thread_id # Simple offset start
                            for i in range(min(extranonce2_size_local, 8)): # Max 8 bytes for 64-bit offset
                                extranonce2_bin_local[i] = (start_val >> (i * 8)) & 0xFF
                        # Job details logging will happen outside the lock
                    # else: job stays None, need_new_job is False

                # --- End of Job Acquisition ---

            # --- Process New Job Data (only if need_new_job is true) ---
            if need_new_job:
                # Log job start details
                target_hex = f"{local_share_target:064x}" if share_target_loaded else "NotSet"
                log_msg(logging.INFO, f"[MINER {thread_id}] Starting job {current_job_id_local} (Clean:{'Y' if clean_job_flag else 'N'} E2Size:{extranonce2_size_local} E2Start(LE):{bin_to_hex(extranonce2_bin_local)} NetNB:0x{nbits_local_le:08x} ShareTgt:{target_hex})")

                # --- Hashing Loop (iterates through extranonce2 values for this job) ---
                job_abandoned_by_thread = False
                initial_e2_value = bytes(extranonce2_bin_local) # Remember start E2 for wrap check

                while not job_abandoned_by_thread and not g_shutdown_event.is_set() and not g_connection_lost_event.is_set():

                    # --- Periodically check for newer job / target update ---
                    if random.randint(0, 10) == 0: # Check occasionally
                         with g_job_lock:
                             if g_job_id != current_job_id_local:
                                 log_msg(logging.INFO, f"[MINER {thread_id}] New job {g_job_id} received while working on {current_job_id_local}. Abandoning old job.")
                                 job_abandoned_by_thread = True
                                 break # Exit E2 loop
                             # Check target consistency
                             with g_share_target_lock:
                                 if g_share_target <= 0:
                                      log_msg(logging.WARNING, f"[WARN][MINER {thread_id}] Global share target became zero mid-job {current_job_id_local}. Abandoning work.")
                                      share_target_loaded = False
                                      job_abandoned_by_thread = True
                                      break # Exit E2 loop
                                 elif share_target_loaded and g_share_target != local_share_target:
                                      log_msg(logging.INFO, f"[MINER {thread_id}] Share target updated mid-job {current_job_id_local}. Applying.")
                                      local_share_target = g_share_target
                                      # Continue with new target

                    if job_abandoned_by_thread: break

                    # --- Calculate Merkle Root --- Use local variables ---
                    try:
                        # Pass the local copies of job data to the function
                        current_merkle_root_le = calculate_simplified_merkle_root_le(
                            coinb1_local_bin, extranonce1_local_bin, extranonce2_bin_local, # Use local versions
                            coinb2_local_bin, merkle_branch_local_bin_be)                  # Use local versions
                        if not current_merkle_root_le or len(current_merkle_root_le) != 32:
                            log_msg(logging.ERROR, f"[MINER {thread_id}] Failed to calculate merkle root for job {current_job_id_local}. Abandoning.")
                            job_abandoned_by_thread = True
                            continue # To break outer loop
                    except Exception as e:
                        log_msg(logging.ERROR, f"[MINER {thread_id}] Exception calculating merkle root for job {current_job_id_local}: {e}. Abandoning.")
                        job_abandoned_by_thread = True
                        continue # To break outer loop


                    # --- Construct Block Header Template (first 76 bytes) --- Use local variables ---
                    try:
                        header_template_le = struct.pack('<I', version_local_le) + \
                                             prevhash_local_bin_le + \
                                             current_merkle_root_le + \
                                             struct.pack('<I', ntime_local_le) + \
                                             struct.pack('<I', nbits_local_le)
                        if len(header_template_le) != 76:
                             log_msg(logging.ERROR, f"[MINER {thread_id}] Incorrect header template length ({len(header_template_le)}) for job {current_job_id_local}. Abandoning.")
                             job_abandoned_by_thread = True
                             continue
                    except struct.error as e:
                         log_msg(logging.ERROR, f"[MINER {thread_id}] Failed to pack header template for job {current_job_id_local}: {e}. Abandoning.")
                         job_abandoned_by_thread = True
                         continue
                    except Exception as e:
                         log_msg(logging.ERROR, f"[MINER {thread_id}] Unexpected error building header template for job {current_job_id_local}: {e}. Abandoning.")
                         job_abandoned_by_thread = True
                         continue

                    # --- Nonce Loop ---
                    # Python doesn't have SSE, so we just iterate nonces linearly within the thread's slice
                    # Simple distribution: each thread handles nonces congruent to its ID mod num_threads
                    nonce_limit = 0xFFFFFFFF # 2^32 - 1
                    nonce_start = thread_id
                    nonce_step = num_threads

                    hash_counter_batch = 0 # Count hashes in this batch for reporting

                    for nonce_le_int in range(nonce_start, nonce_limit + 1, nonce_step):
                        # --- Periodic checks ---
                        if (nonce_le_int & 0xFFFF) == (thread_id & 0xFFFF): # Check roughly every 65k nonces per thread
                            if g_shutdown_event.is_set() or g_connection_lost_event.is_set():
                                job_abandoned_by_thread = True
                                break
                            # Non-blocking check for new job/target
                            with g_job_lock:
                                if g_job_id != current_job_id_local:
                                    job_abandoned_by_thread = True
                                else:
                                    with g_share_target_lock:
                                        if g_share_target <= 0: job_abandoned_by_thread = True; share_target_loaded = False
                                        elif share_target_loaded and g_share_target != local_share_target: local_share_target = g_share_target # Update target
                            if job_abandoned_by_thread: break

                            # Update hash count periodically
                            if hash_counter_batch > 0:
                                with g_thread_hash_counts_lock:
                                    g_thread_hash_counts[thread_id] += hash_counter_batch
                                hash_counter_batch = 0


                        # --- Prepare 80-byte header with current nonce ---
                        try:
                            nonce_le_bytes = struct.pack('<I', nonce_le_int)
                            header_le = header_template_le + nonce_le_bytes
                        except struct.error:
                            log_msg(logging.WARNING, f"[MINER {thread_id}] Failed to pack nonce {nonce_le_int}. Skipping.")
                            continue

                        # --- Double SHA256 ---
                        final_hash_be = sha256_double_be(header_le)
                        hash_counter_batch += 1

                        # --- Check result against share target ---
                        final_hash_le = final_hash_be[::-1] # Reverse for LE comparison
                        if share_target_loaded and is_hash_less_or_equal_target(final_hash_le, local_share_target):
                            # --- Share Found ---
                            winning_nonce_le = nonce_le_int
                            hash_hex_be = bin_to_hex(final_hash_be)
                            share_timestamp = timestamp_us()

                            # Check against network target (for logging '[BLOCK!]')
                            # Note: This check in Python might be slightly different than the C++ bitwise check if edge cases exist
                            network_difficulty = calculate_difficulty_nbits(nbits_local_le)
                            share_difficulty = calculate_difficulty_from_target(int.from_bytes(final_hash_le, 'little'))
                            meets_network_target = (network_difficulty > 0 and share_difficulty >= network_difficulty) # Approx check

                            # Print to stdout/stderr
                            print(f"\r{' '*80}\r", end='', file=sys.stderr) # Clear line
                            print(f"{C_GREEN}[T{thread_id} {share_timestamp}] Share found! Job: {current_job_id_local} Nonce: 0x{winning_nonce_le:08x} {'[BLOCK!]' if meets_network_target else ''}{C_RESET}", flush=True)

                            target_hex_log = f"{local_share_target:064x}"
                            log_msg(logging.INFO, f"[SHARE FOUND][T{thread_id}] Job={current_job_id_local} N(LE)=0x{winning_nonce_le:08x} H(BE)={hash_hex_be} Tgt={target_hex_log} E2(LE)={bin_to_hex(extranonce2_bin_local)} {'[BLOCK!]' if meets_network_target else ''}")

                            # --- Submit Share ---
                            ntime_hex_be = uint32_to_hex_be(ntime_local_le)
                            nonce_hex_be = uint32_to_hex_be(winning_nonce_le)
                            extranonce2_hex = bin_to_hex(extranonce2_bin_local)
                            submit_id = int(time.time() * 1000) + thread_id # Reasonably unique ID

                            payload = {
                                "id": submit_id,
                                "method": "mining.submit",
                                "params": [
                                    g_wallet_addr,
                                    current_job_id_local,
                                    extranonce2_hex,
                                    ntime_hex_be,
                                    nonce_hex_be
                                ]
                            }
                            # Send submission
                            with g_socket_lock:
                                current_socket = g_socket
                            if current_socket:
                                if send_json_message(current_socket, payload):
                                    log_msg(logging.INFO, f"[SUBMIT][T{thread_id}] Submitted share ID {submit_id} for job {current_job_id_local}")
                                else:
                                    log_msg(logging.ERROR, f"[SUBMIT][T{thread_id}] Failed to send share ID {submit_id} for job {current_job_id_local} (connection issue?)")
                                    # Connection lost event should be set by send_json_message on failure
                            else:
                                 log_msg(logging.ERROR, f"[SUBMIT][T{thread_id}] Cannot submit share ID {submit_id} - No active socket.")
                                 g_connection_lost_event.set() # Assume connection is lost

                            job_abandoned_by_thread = True # Found share, stop working on this extranonce2
                            break # Exit the nonce loop

                    # --- End of Nonce Loop ---

                    # Update remaining hashes from the loop
                    if hash_counter_batch > 0:
                        with g_thread_hash_counts_lock:
                           g_thread_hash_counts[thread_id] += hash_counter_batch
                        hash_counter_batch = 0

                    # If job was abandoned (share found, new job, shutdown, error), break extranonce2 loop
                    if job_abandoned_by_thread:
                        break

                    # --- Increment Extranonce2 (Little Endian) ---
                    if not increment_extranonce2(extranonce2_bin_local):
                        # Full wrap-around occurred
                        log_msg(logging.WARNING, f"[WARN][T{thread_id}] Extranonce2 space fully wrapped for job {current_job_id_local}. E2(LE): {bin_to_hex(extranonce2_bin_local)}. Waiting for new job.")
                        job_abandoned_by_thread = True # Mark job as done for this thread
                        break # Exit E2 loop
                    else:
                        # Simple check if E2 returned to its starting value for this thread
                        # This isn't perfectly robust for exhaustion detection across threads,
                        # but matches the C++ 'wrap' check logic more closely.
                        if bytes(extranonce2_bin_local) == initial_e2_value and extranonce2_size_local > 0:
                           log_msg(logging.WARNING, f"[WARN][T{thread_id}] Extranonce2 space potentially exhausted (returned to start value) for job {current_job_id_local}. Waiting for new job.")
                           job_abandoned_by_thread = True # Treat as exhausted for this thread
                           break # Exit E2 loop
                    # If not wrapped, loop continues with next extranonce2 value

                # --- End of Extranonce2 Loop ---
            # --- End of if (need_new_job) ---
            else:
                # If we woke up but didn't process a job (spurious, target not ready, race condition)
                # Add a small sleep to prevent potential busy-waiting.
                if not g_shutdown_event.is_set() and not g_connection_lost_event.is_set():
                     time.sleep(0.02) # 20ms sleep

        # --- End of Main Mining Loop (while not g_shutdown_event.is_set()) ---

    except Exception as e:
        log_msg(logging.ERROR, f"[FATAL][MINER {thread_id}] Terminating due to exception: {e}")
        import traceback
        log_msg(logging.ERROR, traceback.format_exc())
        g_connection_lost_event.set() # Signal loss
        with g_job_lock:
            g_new_job_condition.notify_all() # Wake others

    # --- Cleanup Actions before thread exits ---
    if not g_shutdown_event.is_set() and not g_connection_lost_event.is_set():
        log_msg(logging.WARNING, f"[MINER {thread_id}] Exiting unexpectedly, signaling connection lost.")
        g_connection_lost_event.set()
        with g_job_lock:
            g_new_job_condition.notify_all()

    log_msg(logging.INFO, f"[MINER {thread_id}] Thread finished.")
# --- End of miner_func ---


# --- Subscribe Thread ---
def subscribe_func():
    """Handles Stratum protocol communication (subscribe, authorize, jobs, difficulty)."""
    global g_socket # Access global socket reference
    thread_name = "Subscribe"
    threading.current_thread().name = thread_name
    log_msg(logging.INFO, "[SUB] Subscribe thread started.")

    buffer_agg = "" # Aggregated data buffer

    time.sleep(0.2) # Wait a bit for main thread to potentially connect

    while not g_shutdown_event.is_set():
        sock_to_use = None
        with g_socket_lock:
            if g_socket:
               sock_to_use = g_socket
            else:
               # Socket not ready or already closed by main thread
               time.sleep(1)
               continue

        log_msg(logging.INFO, f"[SUB] Socket FD {sock_to_use.fileno() if sock_to_use else 'N/A'} valid. Sending subscribe/authorize.")

        # Send subscribe
        subscribed = send_json_message(sock_to_use, {"id": 1, "method": "mining.subscribe", "params": ["SimplePythonMiner/1.0"]})
        if not subscribed:
            log_msg(logging.ERROR, "[SUB] Send subscribe failed. Waiting for reconnect.")
            # Rely on main loop to handle reconnect based on g_connection_lost_event
            time.sleep(RECONNECT_DELAY_SECONDS)
            continue

        # Send authorize
        authed = send_json_message(sock_to_use, {"id": 2, "method": "mining.authorize", "params": [g_wallet_addr, g_pool_password]})
        if not authed:
            log_msg(logging.ERROR, "[SUB] Send authorize failed. Waiting for reconnect.")
             # Rely on main loop
            time.sleep(RECONNECT_DELAY_SECONDS)
            continue

        buffer_agg = "" # Clear any previous buffer data
        log_msg(logging.INFO, f"[SUB] Waiting for pool messages on FD {sock_to_use.fileno()}...")

        # Inner loop: Process messages while connected and using this socket
        try:
            while not g_shutdown_event.is_set():
                 # Check if the global socket has changed or been closed
                 with g_socket_lock:
                     if g_socket != sock_to_use:
                         log_msg(logging.INFO, f"[SUB] Socket FD {sock_to_use.fileno()} closed externally or changed. Exiting receive loop.")
                         break # Exit inner loop, main loop will handle state

                 # Use select for non-blocking read check with timeout
                 ready_to_read, _, _ = select.select([sock_to_use], [], [], 2.0) # 2 second timeout

                 if not ready_to_read:
                      # Timeout, check shutdown/socket change again
                      continue

                 # Data available, try to read
                 chunk = sock_to_use.recv(8192)
                 if not chunk:
                     # Connection closed gracefully by pool
                     log_msg(logging.INFO, f"[SUB] Pool disconnected FD {sock_to_use.fileno()} (read 0 bytes).")
                     raise socket.error("Pool closed connection") # Trigger reconnect

                 # Process received data
                 buffer_agg += chunk.decode('utf-8', errors='replace') # Decode assuming UTF-8

                 # Process line by line from aggregated buffer
                 while '\n' in buffer_agg:
                     line, buffer_agg = buffer_agg.split('\n', 1)
                     line = line.strip()
                     if not line: continue # Skip empty lines

                     # Parse JSON
                     try:
                         message = json.loads(line)
                         # log_msg(logging.DEBUG, f"[DEBUG][SUB] Recv: {line}")
                     except json.JSONDecodeError:
                         log_msg(logging.ERROR, f"[ERROR][SUB] JSON parse error for line: {line[:200]}")
                         continue # Skip this line, try next

                     # Process the parsed message
                     process_pool_message(message, line) # Pass original line for logging errors

                 # Check after processing potential messages if we should exit
                 if g_shutdown_event.is_set() or g_connection_lost_event.is_set():
                      break # Exit inner loop

            # --- End inner message processing loop ---

        except socket.timeout:
            # This shouldn't happen with select, but handle defensively
             log_msg(logging.WARNING, "[SUB] Socket timeout during recv (unexpected).")
             continue # Continue outer loop to check socket state
        except socket.error as e:
            # Handle socket errors (connection reset, broken pipe, etc.)
            log_msg(logging.ERROR, f"[ERR][SUB] Socket error on FD {sock_to_use.fileno()}: {e}")
            g_connection_lost_event.set() # Signal connection lost
            with g_job_lock:
                 g_new_job_condition.notify_all() # Wake threads
            # Break inner loop automatically due to exception
        except Exception as e:
            log_msg(logging.ERROR, f"[FATAL][SUB] Unexpected error in receive loop: {e}")
            import traceback
            log_msg(logging.ERROR, traceback.format_exc())
            g_connection_lost_event.set()
            with g_job_lock:
                g_new_job_condition.notify_all()
            # Break inner loop

        # --- After exiting inner loop ---
        if g_shutdown_event.is_set():
            log_msg(logging.INFO, "[SUB] Shutdown signal received, exiting.")
            break # Exit outer loop

        log_msg(logging.INFO, f"[SUB] Exited receive loop for FD {sock_to_use.fileno()}. Assuming connection lost or socket changed.")
        if not g_connection_lost_event.is_set():
            # If the event wasn't set by an error, set it now to trigger reconnect
            g_connection_lost_event.set()
            with g_job_lock:
                g_new_job_condition.notify_all()

        time.sleep(0.5) # Small delay before potentially retrying outer loop

    # --- End main subscribe loop ---
    log_msg(logging.INFO, "[SUB] Subscribe thread finished.")

# --- Process Pool Messages ---
def process_pool_message(message, original_line=""):
    """Parses and handles messages received from the pool."""
    global g_extranonce1_bin, g_extranonce2_size, g_job_id, g_prevhash_bin
    global g_coinb1_bin, g_coinb2_bin, g_merkle_branch_bin_be, g_version_le
    global g_nbits_le, g_ntime_le, g_clean_jobs, g_new_job_available, g_share_target
    global g_current_height

    msg_id = message.get('id')
    method = message.get('method')
    params = message.get('params')
    result = message.get('result')
    error = message.get('error')

    try: # Wrap processing in a try block
        if msg_id is not None: # It's a Response
            if error: # Error Response
                err_str = json.dumps(error)
                log_msg(logging.ERROR, f"[ERR][SUB] Pool error response ID {msg_id}: {err_str}")
                print(f"\r{' '*80}\r{C_RED}[{timestamp_us()}] Pool Error (ID {msg_id}): {err_str}{C_RESET}", file=sys.stderr, flush=True)

                if msg_id == 1: # Subscribe failed
                    raise RuntimeError("Subscribe failed via pool error response")
                elif msg_id == 2: # Authorize failed
                    print(f"\r{' '*80}\r{C_RED}[{timestamp_us()}] AUTH FAILED: {err_str}{C_RESET}", file=sys.stderr, flush=True)
                    raise RuntimeError("Authorization failed via pool error response")
                elif isinstance(msg_id, int) and msg_id >= 100: # Share submission rejected
                    print(f"\r{' '*80}\r{C_RED}[{timestamp_us()}] Share REJECTED (ID {msg_id}): {err_str}{C_RESET}", file=sys.stderr, flush=True)
                    # Continue mining
                # else: Other error response, just log

            elif result is not None or method is None: # Success Response (result can be True, False, null, or data)
                if msg_id == 1: # Subscribe Response
                    # Expected format: result = [ ["mining.notify", subscription_id], extranonce1_hex, extranonce2_size ]
                    # Sometimes the inner list is omitted: result = [ subscription_details, extranonce1_hex, extranonce2_size ]
                    if isinstance(result, list) and len(result) >= 2:
                        try:
                           e1h_idx, e2s_idx = -1, -1
                           # Find hex string (extranonce1) and integer (extranonce2_size)
                           for i, item in enumerate(result):
                               if isinstance(item, str) and len(item) % 2 == 0: # Potential hex
                                   try: binascii.unhexlify(item); e1h_idx = i; break # Found valid hex
                                   except: pass
                           for i, item in enumerate(result):
                               if isinstance(item, int): e2s_idx = i; break # Found integer

                           if e1h_idx != -1 and e2s_idx != -1:
                               e1h = result[e1h_idx]
                               e2s_i = result[e2s_idx]
                               e1b = hex_to_bin(e1h)
                               if e1b is not None:
                                   with g_job_lock:
                                       g_extranonce1_bin = e1b
                                       g_extranonce2_size = int(e2s_i)
                                       log_msg(logging.INFO, f"[SUB] Subscribe OK. E1: {e1h} ({len(g_extranonce1_bin)}B), E2Size: {g_extranonce2_size}")
                                       print(f"[POOL] Subscribe OK. Extranonce2 Size: {g_extranonce2_size}", flush=True)
                               else:
                                    log_msg(logging.ERROR, f"[ERR][SUB] Failed to convert extranonce1 hex '{e1h}'")
                                    raise RuntimeError("Failed to parse extranonce1 from subscribe response")
                           else:
                               log_msg(logging.ERROR, f"[ERR][SUB] Could not find extranonce1(hex) and extranonce2_size(int) in subscribe result: {result}")
                               raise RuntimeError("Invalid subscribe response format (missing e1/e2s)")
                        except Exception as e:
                            log_msg(logging.ERROR, f"[ERR][SUB] Error processing subscribe result: {e} - Result: {result}")
                            raise RuntimeError(f"Error processing subscribe response: {e}")
                    else:
                        log_msg(logging.ERROR, f"[ERR][SUB] Invalid subscribe response format (structure): {result}")
                        raise RuntimeError("Invalid subscribe response format (structure)")

                elif msg_id == 2: # Authorize Response
                    auth_ok = bool(result) # True if result is truthy (True, non-empty list/dict, etc.), False if False/None/0
                    log_msg(logging.INFO, f"[SUB] Authorization {'successful' if auth_ok else 'failed'}.")
                    if auth_ok:
                        print(f"{C_GREEN}[POOL] Authorization OK.{C_RESET}", flush=True)
                    else:
                         err_str = json.dumps(result) # Show the actual result if !auth_ok
                         print(f"\r{' '*80}\r{C_RED}[{timestamp_us()}] AUTHORIZATION FAILED! Result: {err_str}. Check wallet/password.{C_RESET}", file=sys.stderr, flush=True)
                         raise RuntimeError("Authorization failed")

                elif isinstance(msg_id, int) and msg_id >= 100: # Share Submit Response
                    share_accepted = bool(result) # True if result is True, False otherwise (null maps to False)
                    if share_accepted:
                        log_msg(logging.INFO, f"[SUB] Share (ID {msg_id}) accepted by pool.")
                        print(f"{C_GREEN}[{timestamp_us()}] Share Accepted! (ID {msg_id}){C_RESET}", flush=True)
                    else:
                        res_str = json.dumps(result)
                        log_msg(logging.WARNING, f"[WARN][SUB] Share (ID {msg_id}) rejected by pool. Result: {res_str}")
                        print(f"\r{' '*80}\r{C_YELLOW}[{timestamp_us()}] Share Rejected? (ID {msg_id}) Result: {res_str}{C_RESET}", file=sys.stderr, flush=True)
                else:
                    log_msg(logging.WARNING, f"[WARN][SUB] Received success result for unexpected ID: {msg_id}, Result: {json.dumps(result)}")
            # else: No error and no result? Log maybe.
            #     log_msg(logging.WARNING, f"[WARN][SUB] Response received for ID {msg_id} with no 'result' and no 'error' field.")

        elif method: # It's a Notification
            if method == "mining.notify":
                # --- Handle mining.notify ---
                if isinstance(params, list) and len(params) >= 9:
                    try:
                        job_id_str, ph_h, cb1_h, cb2_h, mb_hex_list, v_h, nb_h, nt_h, clean_j = params[:9]

                        # --- Acquire lock and update job details ---
                        with g_job_lock:
                            # Convert and validate hex data
                            tph_be = hex_to_bin(ph_h)
                            tcb1 = hex_to_bin(cb1_h)
                            tcb2 = hex_to_bin(cb2_h)
                            tmbl_be = [hex_to_bin(h) for h in mb_hex_list]

                            # Check conversions
                            if tph_be is None or len(tph_be) != 32: raise ValueError(f"Bad prevhash hex '{ph_h}'")
                            if tcb1 is None: raise ValueError(f"Bad coinb1 hex '{cb1_h}'")
                            if tcb2 is None: raise ValueError(f"Bad coinb2 hex '{cb2_h}'")
                            if not all(b is not None and len(b) == 32 for b in tmbl_be): raise ValueError(f"Bad merkle branch hex list")

                            # Convert V, NB, NT from hex BE to integer LE
                            t_v = int.from_bytes(hex_to_bin(v_h), 'big')
                            t_nb = int.from_bytes(hex_to_bin(nb_h), 'big')
                            t_nt = int.from_bytes(hex_to_bin(nt_h), 'big')

                            # Commit changes to global state
                            g_job_id = job_id_str
                            g_prevhash_bin = tph_be[::-1] # Reverse BE hash to store LE prevhash
                            g_coinb1_bin = tcb1
                            g_coinb2_bin = tcb2
                            g_merkle_branch_bin_be = tmbl_be # Store BE list
                            g_version_le = t_v # Already in host integer format
                            g_nbits_le = t_nb # Already in host integer format
                            g_ntime_le = t_nt # Already in host integer format
                            g_clean_jobs = bool(clean_j)
                            g_new_job_available = True

                            # --- Log Job Info & Notify Miners ---
                            new_block = (ph_h != getattr(process_pool_message, "last_ph_hex", "")) # Track block changes
                            process_pool_message.last_ph_hex = ph_h # Store for next comparison

                            if new_block:
                                with g_current_height_lock:
                                    if g_current_height > 0: g_current_height += 1
                                    ch = g_current_height # Local copy for logging
                                net_diff = calculate_difficulty_nbits(g_nbits_le)
                                log_msg(logging.INFO, f"[JOB] New Block ~{ch if ch > 0 else 0}. Job: {job_id_str} (Clean:{'Y' if g_clean_jobs else 'N'} Diff:{net_diff:.3f} nBits:0x{g_nbits_le:08x})")
                                print(f"\r{' '*80}\r{C_YELLOW}[*] New Block ~{ch if ch>0 else 0} | NetDiff: {net_diff:.3e} | Job: {job_id_str}{C_RESET}", flush=True)
                            else:
                                log_msg(logging.INFO, f"[JOB] New Job: {job_id_str} (Clean:{'Y' if g_clean_jobs else 'N'})")

                            # Notify waiting miner threads
                            g_new_job_condition.notify_all()
                        # --- End Job Lock ---

                    except (ValueError, TypeError, IndexError, struct.error) as e:
                         log_msg(logging.ERROR, f"[ERR][SUB] mining.notify message has incorrect parameter types/values: {e}. Line: {original_line[:200]}")
                    except Exception as e:
                         log_msg(logging.ERROR, f"[ERR][SUB] Unexpected error processing mining.notify: {e}. Line: {original_line[:200]}")
                else:
                     log_msg(logging.ERROR, f"[ERR][SUB] Bad notify params structure. Line: {original_line[:200]}")

            elif method == "mining.set_difficulty":
                # --- Handle mining.set_difficulty ---
                if isinstance(params, list) and len(params) > 0:
                    pool_difficulty = params[0]
                    if isinstance(pool_difficulty, (int, float)) and pool_difficulty > 0:
                        log_msg(logging.INFO, f"[SUB] Received pool difficulty: {pool_difficulty:.5f}")
                        print(f"[POOL] Difficulty set to: {pool_difficulty:.5f}", flush=True)

                        # --- Calculate Share Target from Pool Difficulty ---
                        # Target = Target1 / Difficulty
                        try:
                            # Use float for calculation robustness
                            new_target_f = float(TARGET1) / float(pool_difficulty)
                            # Convert to integer, clamping ensures it's within 256 bits and positive
                            new_target_int = max(1, min(int(new_target_f), MAX_TARGET_256))

                            with g_share_target_lock:
                                g_share_target = new_target_int

                            actual_share_diff = calculate_difficulty_from_target(g_share_target)
                            target_hex_log = f"{g_share_target:064x}"
                            log_msg(logging.INFO, f"[SUB] Updated Share Target to {target_hex_log}. PoolDiff: {pool_difficulty:.5f} -> Actual ShareDiff: {actual_share_diff:.5f}")

                        except (ZeroDivisionError, OverflowError, ValueError) as e:
                             log_msg(logging.ERROR, f"[ERR][SUB] Error calculating share target from difficulty {pool_difficulty}: {e}")
                        except Exception as e:
                             log_msg(logging.ERROR, f"[ERR][SUB] Unexpected error calculating share target: {e}")

                    else:
                        log_msg(logging.WARNING, f"[WARN][SUB] Difficulty has invalid type/value ({type(pool_difficulty)}): {pool_difficulty}. Ignoring.")
                        print(f"[POOL] Difficulty has type {type(pool_difficulty)}: {pool_difficulty} (Ignored)", flush=True)
                else:
                     log_msg(logging.WARNING, f"[WARN][SUB] Bad set_difficulty params structure (not list or empty). Params: {params}")
            else:
                log_msg(logging.WARNING, f"[WARN][SUB] Received unknown notification method: {method}, Params: {params}")
        else:
             log_msg(logging.WARNING, f"[WARN][SUB] Received message with no ID and no method: {original_line[:200]}")

    except RuntimeError as e: # Catch critical errors like auth/sub failure
        log_msg(logging.ERROR, f"[FATAL][SUB] Runtime error processing message: {e}. Signaling loss.")
        g_connection_lost_event.set()
        with g_job_lock: g_new_job_condition.notify_all()
        raise # Re-raise to potentially stop the subscribe thread immediately
    except Exception as e:
        log_msg(logging.ERROR, f"[ERROR][SUB] Exception processing message: {e}. Line: {original_line[:200]}")
        import traceback
        log_msg(logging.ERROR, traceback.format_exc())
        # Decide if this error is fatal or recoverable

# --- Periodic Status Logger ---
def log_periodic_status():
    global g_total_hashes_reported, g_aggregated_hash_rate, g_last_aggregated_report_time

    now = time.monotonic()
    duration = now - g_last_aggregated_report_time

    if duration < 0.1: return # Minimum 100ms interval

    # Get current total hashes from threads
    current_total_hashes = 0
    with g_thread_hash_counts_lock:
        current_total_hashes = sum(g_thread_hash_counts)

    delta_hashes = current_total_hashes - g_total_hashes_reported
    if delta_hashes < 0: delta_hashes = 0 # Handle counter reset or race condition

    # Calculate rate in H/s
    current_rate = (delta_hashes / duration) if duration > 0 else 0.0

    # Update global state
    g_aggregated_hash_rate = current_rate
    g_total_hashes_reported = current_total_hashes # Update total count reported
    g_last_aggregated_report_time = now

    # Get other status info
    with g_current_height_lock: height_local = g_current_height
    with g_job_lock: nbits_net_local_le = g_nbits_le # Read under lock
    with g_share_target_lock: current_share_target_copy = g_share_target

    difficulty_share_local = calculate_difficulty_from_target(current_share_target_copy) if current_share_target_copy > 0 else 0.0
    difficulty_net_local = calculate_difficulty_nbits(nbits_net_local_le)

    # Format hashrate for display
    display_rate = current_rate
    rate_unit = "H/s"
    if display_rate >= 1e12: display_rate /= 1e12; rate_unit = "TH/s"
    elif display_rate >= 1e9: display_rate /= 1e9; rate_unit = "GH/s"
    elif display_rate >= 1e6: display_rate /= 1e6; rate_unit = "MH/s"
    elif display_rate >= 1e3: display_rate /= 1e3; rate_unit = "kH/s"

    # Log to file
    log_msg(logging.INFO, f"[STATUS] Height: ~{height_local if height_local>0 else 0} | NetDiff: {difficulty_net_local:.3f} | ShareDiff: {difficulty_share_local:.3f} | Rate: {display_rate:.2f} {rate_unit}")

    # Print status to stderr (overwriting previous line)
    status_line = f"[{timestamp_us()}] [STATUS] H: ~{height_local if height_local>0 else 0} | NetD: {difficulty_net_local:.3e} | ShareD: {difficulty_share_local:.3f} | Rate: {display_rate:.2f} {rate_unit}"
    print(f"\r{' '*80}\r{C_CYAN}{status_line}{C_RESET}", end='', file=sys.stderr)
    sys.stderr.flush()


# --- Main Function ---
def main():
    global g_socket, g_thread_hash_counts
    global g_total_hashes_reported, g_aggregated_hash_rate, g_last_aggregated_report_time
    global g_job_id, g_prevhash_bin, g_coinb1_bin, g_coinb2_bin, g_merkle_branch_bin_be
    global g_version_le, g_nbits_le, g_ntime_le, g_clean_jobs, g_new_job_available
    global g_extranonce1_bin, g_extranonce2_size, g_share_target, g_current_height

    # --- Signal Handling ---
    signal.signal(signal.SIGINT, handle_sigint)
    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN) # Ignore SIGPIPE on POSIX

    # --- Load Configuration ---
    print(f"Loading configuration from {CONFIG_FILE}...")
    if not load_config():
        sys.exit(1)

    # --- Setup File Logger (now that g_log_file is known) ---
    setup_file_logger()

    # --- Start Logging ---
    log_msg(logging.INFO,"--------------------------------------------------")
    log_msg(logging.INFO,"Miner starting with configuration:")
    log_msg(logging.INFO,f"  Pool: {g_pool_host}:{g_pool_port}")
    log_msg(logging.INFO,f"  Wallet/Worker: {g_wallet_addr}")
    log_msg(logging.INFO,f"  Password: {'[empty]' if not g_pool_password else '(set)'}") # Don't log password
    log_msg(logging.INFO,f"  Log File: {g_log_file}")
    log_msg(logging.INFO,f"  Threads: {g_threads}")
    log_msg(logging.INFO,"--------------------------------------------------")

    # --- Check CPU Features (Omitted - Python doesn't use SSE) ---
    # print("Checking CPU features...")
    # print("[INFO] CPU Features: SSE check skipped for Python version.")

    # --- Display Basic Info ---
    print(f"{C_MAG}----------------------------------------{C_RESET}")
    print(f"{C_MAG} Wallet: {C_YELLOW}{g_wallet_addr}{C_RESET}")
    print(f"{C_MAG} Threads: {C_YELLOW}{g_threads}{C_RESET}")
    print(f"{C_MAG} Pool: {C_YELLOW}{g_pool_host}:{g_pool_port}{C_RESET}")
    print(f"{C_MAG}----------------------------------------{C_RESET}")
    sys.stdout.flush()

    # --- Initialize Hashrate Counters ---
    with g_thread_hash_counts_lock:
        g_thread_hash_counts = [0] * g_threads # Initialize list with zeros
    g_total_hashes_reported = 0
    g_aggregated_hash_rate = 0.0
    g_last_aggregated_report_time = time.monotonic()


    # --- Get Initial Block Height ---
    log_msg(logging.INFO,"[MAIN] Fetching initial block height...")
    print("[INFO] Fetching initial block height from API...")
    sys.stdout.flush()
    initial_height = get_current_block_height()
    with g_current_height_lock:
        g_current_height = initial_height # Store initial height (-1 if failed)
    if initial_height > 0:
        print(f"{C_CYAN}[INFO] Initial block height estimated at: {initial_height}{C_RESET}")
        log_msg(logging.INFO, f"[MAIN] Initial block height from API: {initial_height}")
    else:
        print(f"{C_YELLOW}[WARN] Could not fetch initial block height from API.{C_RESET}")
        log_msg(logging.WARNING, "[WARN] Failed to fetch initial block height from API.")
    sys.stdout.flush()

    # --- Timers for Periodic Tasks ---
    height_check_interval = 15 * 60 # 15 minutes
    last_height_check_time = time.monotonic()
    status_log_interval = STATUS_LOG_INTERVAL_SECONDS
    last_status_log_time = time.monotonic()

    threads = [] # To keep track of running threads

    # --- Main Reconnect Loop ---
    while not g_shutdown_event.is_set():
        log_msg(logging.INFO, f"[MAIN] Attempting connection to pool {g_pool_host}:{g_pool_port}...")
        print(f"[NET] Connecting to {g_pool_host}:{g_pool_port}...")
        sys.stdout.flush()

        # Reset connection lost flag and potentially clear old job data for new attempt
        g_connection_lost_event.clear()
        with g_thread_hash_counts_lock:
            g_thread_hash_counts = [0] * g_threads # Reset counters
        g_total_hashes_reported = 0
        g_aggregated_hash_rate = 0.0
        g_last_aggregated_report_time = time.monotonic()

        # Attempt connection
        new_socket = connect_pool()

        if new_socket is None:
            log_msg(logging.WARNING, f"[MAIN] Connection failed. Retrying in {RECONNECT_DELAY_SECONDS} seconds...")
            print(f"{C_YELLOW}[NET] Connection failed. Retrying in {RECONNECT_DELAY_SECONDS} seconds...{C_RESET}", file=sys.stderr)
            sys.stderr.flush()
            # Wait for reconnect delay, but allow shutdown signal to interrupt
            g_shutdown_event.wait(timeout=RECONNECT_DELAY_SECONDS)
            if g_shutdown_event.is_set(): break # Exit main loop if shutdown during wait
            continue # Try connecting again

        # --- Connection Successful ---
        with g_socket_lock:
             g_socket = new_socket # Store the valid socket globally
        log_msg(logging.INFO, f"[MAIN] Connection successful (FD/Socket: {g_socket.fileno()}). Starting threads...")
        print(f"{C_GREEN}[NET] Connected! Starting {g_threads} worker threads.{C_RESET}")
        sys.stdout.flush()

        # Reset Global Job State Variables (under lock)
        with g_job_lock:
            log_msg(logging.INFO, "[MAIN] Resetting job state for new connection.")
            g_job_id = None
            g_prevhash_bin = b''
            g_coinb1_bin = b''
            g_coinb2_bin = b''
            g_merkle_branch_bin_be = []
            g_version_le = 0
            g_nbits_le = 0
            g_ntime_le = 0
            g_clean_jobs = False
            g_new_job_available = False
            g_extranonce1_bin = b''
            g_extranonce2_size = 4 # Reset to default
        # Reset Share Target to Diff 1 (pool will send actual difficulty)
        with g_share_target_lock:
            g_share_target = TARGET1
            log_msg(logging.INFO, "[MAIN] Reset share target to Difficulty 1 for new connection.")

        # Start Threads
        threads = []
        sub_thread = threading.Thread(target=subscribe_func, name="Subscribe", daemon=True)
        threads.append(sub_thread)
        sub_thread.start()

        for i in range(g_threads):
            miner_thread = threading.Thread(target=miner_func, args=(i, g_threads), name=f"Miner-{i}", daemon=True)
            threads.append(miner_thread)
            miner_thread.start()

        # --- Monitor Loop (while connected) ---
        while not g_shutdown_event.is_set() and not g_connection_lost_event.is_set():
            # Wait for a short duration or until notified of shutdown/disconnect
            # Use event wait with timeout
            signaled = g_shutdown_event.wait(timeout=1.0) # Check every second
            if signaled or g_connection_lost_event.is_set():
                break # Exit monitor loop if shutdown or lost connection signaled

             # Perform periodic tasks
            now_monotonic = time.monotonic()
            if now_monotonic - last_status_log_time >= status_log_interval:
                try:
                    log_periodic_status()
                except Exception as e: # Catch errors in status logging
                    log_msg(logging.ERROR, f"[ERROR][STATUS] Error during periodic status log: {e}")
                last_status_log_time = now_monotonic

            if now_monotonic - last_height_check_time >= height_check_interval:
                log_msg(logging.INFO, "[MAIN] Performing periodic external height check...")
                external_height = get_current_block_height()
                if external_height > 0:
                    with g_current_height_lock:
                        local_height = g_current_height
                        if external_height > local_height:
                            log_msg(logging.INFO, f"[MAIN] External height {external_height} > local height {local_height}. Updating local height.")
                            print(f"\n{C_CYAN}[INFO] External height update detected: {external_height}{C_RESET}", flush=True)
                            g_current_height = external_height # Update atomic height
                        elif external_height < local_height and local_height > 0:
                            log_msg(logging.WARNING, f"[WARN][MAIN] External height {external_height} < local height {local_height}. Ignoring minor discrepancy.")
                else:
                    log_msg(logging.WARNING, "[WARN][MAIN] Periodic external height check failed.")
                last_height_check_time = now_monotonic

        # --- End Monitor Loop ---

        # --- Disconnection or Shutdown Detected ---
        if g_shutdown_event.is_set():
             log_msg(logging.INFO, "[MAIN] Shutdown requested. Stopping threads...")
        elif g_connection_lost_event.is_set():
             log_msg(logging.INFO, "[MAIN] Connection lost detected. Stopping threads and preparing to reconnect...")
             ts = timestamp_us()
             print(f"\r{' '*80}\r{C_YELLOW}[{ts}] Pool connection lost. Reconnecting...{C_RESET}", file=sys.stderr, flush=True)

        # --- Coordinated Thread Shutdown ---
        # 1. Close the socket (this should interrupt blocking reads/selects)
        closed_socket_fd = -1
        with g_socket_lock:
             if g_socket:
                 closed_socket_fd = g_socket.fileno()
                 try:
                     g_socket.shutdown(socket.SHUT_RDWR) # Signal intent to close
                 except socket.error: pass # Ignore errors if already closed
                 try:
                     g_socket.close()
                     log_msg(logging.INFO, f"[MAIN] Closed socket FD {closed_socket_fd}.")
                 except socket.error as e:
                     log_msg(logging.WARNING, f"[MAIN] Error closing socket FD {closed_socket_fd}: {e}")
                 g_socket = None # Mark global socket as invalid

        # 2. Ensure events are set to signal threads
        g_connection_lost_event.set() # Ensure this is set
        g_shutdown_event.set() # Ensure this is set if we are shutting down

        # 3. Notify all waiting threads (miners waiting for jobs)
        with g_job_lock:
            g_new_job_condition.notify_all()
        log_msg(logging.INFO, "[MAIN] Notified condition variable for thread shutdown.")

        # 4. Join threads (with timeout) - Daemon threads might exit anyway, but join is cleaner
        log_msg(logging.INFO, f"[MAIN] Joining {len(threads)} threads...")
        join_timeout = 2.0 # Seconds to wait for each thread
        start_join = time.monotonic()
        joined_count = 0
        for t in threads:
             # Check if current thread before joining
             if t == threading.current_thread(): continue
             # Join with timeout
             t.join(timeout=max(0.1, join_timeout - (time.monotonic() - start_join)))
             if t.is_alive():
                 log_msg(logging.WARNING, f"[MAIN] Thread {t.name} did not join within timeout.")
             else:
                 log_msg(logging.INFO, f"[MAIN] Thread {t.name} joined.")
                 joined_count += 1
        threads.clear()
        log_msg(logging.INFO, f"[MAIN] Joined {joined_count} threads.")


        # --- Prepare for Next Loop Iteration (Reconnect Delay) ---
        if g_shutdown_event.is_set():
             log_msg(logging.INFO, "[MAIN] Shutdown confirmed. Exiting main loop.")
             break # Exit the main reconnect loop
        else:
             log_msg(logging.INFO, f"[MAIN] Waiting {RECONNECT_DELAY_SECONDS}s before attempting reconnect...")
             # Wait, allowing interruption by SIGINT
             g_shutdown_event.wait(timeout=RECONNECT_DELAY_SECONDS)
             if g_shutdown_event.is_set(): break # Exit if shutdown during wait

    # --- End Main Reconnect Loop ---

    # --- Final Cleanup ---
    log_msg(logging.INFO, "[MAIN] Miner shutting down cleanly.")
    print(f"\n{C_GREEN}Miner exiting...{C_RESET}")
    sys.stdout.flush()

    # Log final stats (already done in log_periodic_status, but maybe print one last time)
    final_rate = g_aggregated_hash_rate
    final_unit = "H/s"
    if final_rate >= 1e12: final_rate /= 1e12; final_unit = "TH/s"
    elif final_rate >= 1e9: final_rate /= 1e9; final_unit = "GH/s"
    elif final_rate >= 1e6: final_rate /= 1e6; final_unit = "MH/s"
    elif final_rate >= 1e3: final_rate /= 1e3; final_unit = "kH/s"
    final_hashes = g_total_hashes_reported # Get last reported total

    print(f"{C_CYAN}Final Status:{C_RESET} Rate={final_rate:.2f} {final_unit} | Total Hashes (approx)={final_hashes}{C_RESET}", flush=True)
    log_msg(logging.INFO,"----------------- Miner Exited -----------------")

    # Close file handler explicitly if it exists
    if file_handler:
        try:
            file_handler.close()
            logger.removeHandler(file_handler)
        except Exception as e:
             print(f"{C_YELLOW}[WARN] Error closing log file handler: {e}{C_RESET}", file=sys.stderr)


if __name__ == "__main__":
    # Necessary imports for select within subscribe_func if not already global
    import select
    main()
