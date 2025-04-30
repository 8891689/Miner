#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author：8891689
# Assist in creation：gemini
import socket
import json
import time
import threading
import multiprocessing
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
from queue import Queue, Empty, Full

try:
    import requests
except ImportError:
    print("Error: 'requests' library not found. Please install it using: pip install requests")
    sys.exit(1)

# --- Configuration Variables ---
g_pool_host = ""
g_pool_port = 0
g_wallet_addr = ""
g_pool_password = "x"
g_log_file = "miner.log"
g_processes = 0

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

# --- Global State (Main Process / Subscribe Thread) ---
# Multiprocessing events for signaling processes
g_shutdown_event_mp = multiprocessing.Event()
g_connection_lost_event_mp = multiprocessing.Event()

# IPC Queues for communication
job_queue = multiprocessing.Queue(maxsize=1) # Small size to backpressure job producer
submit_queue = multiprocessing.Queue() # Shares found by processes
hash_queue = multiprocessing.Queue() # Hash counts from processes

# Shared memory and lock for state shared between main process and miner processes
shared_target = None # Placeholder for Manager.Value object holding the target integer
shared_target_lock = multiprocessing.Lock() # Lock needed for Manager objects


# Global state for main process/subscribe thread
g_socket = None # Holds the current socket object
g_socket_lock = threading.Lock() # Protect access to g_socket

# Global state for block height in main process/subscribe thread
g_current_height = -1 # Block height, updated from API or job
g_current_height_lock = threading.Lock() # Protect g_current_height

# Hashrate Calculation State (Aggregated in Main Process)
g_process_hash_counts = {} # Dict to store hash counts {process_id: count}
g_total_hashes_reported = 0
g_aggregated_hash_rate = 0.0
g_last_aggregated_report_time = time.monotonic()

# --- Constants ---
# Difficulty 1 target (0x00000000FFFF0000000000000000000000000000000000000000000000000000)
TARGET1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
MAX_TARGET_256 = (1 << 256) - 1
# Initial g_share_target will be set via Manager in main()

# --- Logger Setup ---
log_formatter = logging.Formatter('[%(asctime)s.%(msecs)03d] [%(processName)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

for handler in logger.handlers[:]:
    logger.removeHandler(handler)

file_handler = None

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
    except Exception as e:
        print(f"{C_RED}[!!! LOG FILE SETUP ERROR !!!] Cannot write to '{g_log_file}': {e}{C_RESET}", file=sys.stderr)

def log_msg(level, message):
    """Logs message using the global logger."""
    logger.log(level, message)

def timestamp_us():
    """Gets timestamp string with microseconds."""
    now = datetime.now()
    return now.strftime('%H:%M:%S.%f')[:15]

# --- Helper Functions ---

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
    """Calculates the Merkle Root (LE) from components."""
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
    if not hash_le_bytes or len(hash_le_bytes) != 32 or target_int is None or target_int <= 0:
        return False
    try:
        hash_int = int.from_bytes(hash_le_bytes, 'little')
        return hash_int <= target_int
    except (TypeError, ValueError):
        return False

# Difficulty calculation using nBits
def calculate_difficulty_nbits(nbits_le_int):
    """Calculates difficulty from nBits (Little Endian integer) vs TARGET1."""
    if nbits_le_int is None or nbits_le_int == 0: return 0.0
    try:
        # Convert LE int to BE bytes, then parse exponent and coefficient
        nbits_be_bytes = struct.pack('<I', nbits_le_int)[::-1] # Pack LE, then reverse to get BE bytes
        nbits_be_parsed = struct.unpack('>I', nbits_be_bytes)[0] # Unpack BE bytes as BE int

        exponent = (nbits_be_parsed >> 24) & 0xFF
        coefficient = nbits_be_parsed & 0x00FFFFFF

        if coefficient == 0: return float('inf')
        if exponent < 3 or exponent > 32: return 0.0 # Invalid exponent range for standard BTC

        # Difficulty = TARGET1 / target
        # target = coefficient * 2^(8*(exponent-3))
        # Using float for potentially large numbers
        target = float(coefficient) * math.pow(2.0, 8.0 * (exponent - 3))

        if target == 0: return float('inf')
        difficulty = float(TARGET1) / target
        return difficulty
    except struct.error:
        return 0.0 # Invalid nbits value
    except OverflowError:
        # Calculation might exceed standard float limits, use simplified ratio
        try:
             diff1_coeff = 0x00ffff
             diff1_exp = 0x1d # 29
             diff1_exp_shift = 8 * (diff1_exp - 3)
             current_exp_shift = 8 * (exponent - 3)
             # difficulty = (TARGET1_coeff / current_coeff) * 2^(TARGET1_exp_shift - current_exp_shift)
             # TARGET1_coeff is effectively 0x00ffff, TARGET1_exp is 0x1d (29)
             difficulty = (float(diff1_coeff) / float(coefficient)) * math.pow(2.0, diff1_exp_shift - current_exp_shift)
             return difficulty
        except (OverflowError, ValueError):
             return float('inf') # Or some other indicator of extreme difficulty
    except Exception:
        return 0.0 # Other errors

# Calculate difficulty from a 256-bit target integer
def calculate_difficulty_from_target(target_int):
    """Calculates difficulty from a 256-bit integer target, using TARGET1 for reference."""
    if target_int is None or target_int <= 0:
        return float('inf') # Target too low or invalid means extremely high difficulty
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
        # Pack as little-endian, then reverse bytes to get big-endian representation
        be_bytes = struct.pack('<I', val_le_int)[::-1]
        return bin_to_hex(be_bytes) # Convert BE bytes to hex
    except struct.error:
        return "00000000" # Error case

def increment_extranonce2(enonce2_bytearray):
    """Increments the extranonce2 bytearray (Little Endian). Returns False if wrapped around."""
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
    global g_pool_host, g_pool_port, g_wallet_addr, g_processes
    global g_pool_password, g_log_file

    try:
        with open(CONFIG_FILE, 'r') as f:
            config_content = f.read()
    except FileNotFoundError:
        print(f"{C_RED}[ERROR] Config file '{CONFIG_FILE}' not found.{C_RESET}", file=sys.stderr)
        try:
            with open(CONFIG_FILE, 'w') as f_example:
                example_json = {
                    "pool_host": "stratum.example.com",
                    "pool_port": 3333,
                    "wallet_address": "YOUR_BTC_WALLET_ADDRESS",
                    "processes": 4,
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
        print(f"{C_RED}[ERROR] Failed to parse JSON from config file '{CONFIG_FILE}': {e}{C_RESET}", file=sys.stderr)
        return False

    error_field = ""
    try:
        g_pool_host = config.get("pool_host")
        if isinstance(g_pool_host, str) and g_pool_host.startswith("stratum+tcp://"):
            g_pool_host = g_pool_host[len("stratum+tcp://"):]

        if not isinstance(g_pool_host, str) or not g_pool_host:
            error_field = "pool_host"
            raise ValueError()

        g_pool_port = config.get("pool_port")
        if not isinstance(g_pool_port, int) or not (0 < g_pool_port <= 65535):
            error_field = "pool_port"
            raise ValueError()

        g_wallet_addr = config.get("wallet_address")
        if not isinstance(g_wallet_addr, str) or not g_wallet_addr or g_wallet_addr == "YOUR_BTC_WALLET_ADDRESS":
            error_field = "wallet_address"
            raise ValueError()

        g_processes = config.get("processes")
        if not isinstance(g_processes, int) or g_processes <= 0:
            error_field = "processes"
            raise ValueError()

        g_pool_password = config.get("pool_password", "x")
        if not isinstance(g_pool_password, str):
            error_field = "pool_password"
            raise ValueError()

        g_log_file = config.get("log_file", "miner.log")
        if not isinstance(g_log_file, str) or not g_log_file:
            g_log_file = "miner.log"

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
    """Handles SIGINT signal for graceful shutdown."""
    if g_shutdown_event_mp.is_set():
        return
    print(f"\r{' '*80}\r{C_YELLOW}[SIGNAL] Shutdown initiated by SIGINT...{C_RESET}", file=sys.stderr)
    sys.stderr.flush()
    log_msg(logging.INFO,"[SIGNAL] SIGINT received, initiating shutdown...")
    g_shutdown_event_mp.set()
    g_connection_lost_event_mp.set()

# --- Networking & Pool Communication ---

# Get current block height from an external API
def get_current_block_height():
    url = "https://mempool.space/api/blocks/tip/height"
    headers = {'User-Agent': 'SimplePythonMiner/1.0'}
    try:
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()
        height = int(response.text)
        return height
    except requests.exceptions.RequestException as e:
        log_msg(logging.ERROR, f"[HTTP] Failed to get block height from {url}: {e}")
    except (ValueError, TypeError) as e:
         log_msg(logging.ERROR, f"[HTTP] Failed to parse height response '{response.text[:100]}...': {e}")
    except Exception as e:
         log_msg(logging.ERROR, f"[HTTP] Unknown error getting block height: {e}")
    return -1

# Connect to the mining pool
def connect_pool():
    """Tries to connect to the pool. Returns socket object or None."""
    log_msg(logging.INFO, f"[NET] Resolving {g_pool_host}:{g_pool_port}...")
    sock = None
    try:
        addr_info_list = socket.getaddrinfo(g_pool_host, g_pool_port, socket.AF_UNSPEC, socket.SOCK_STREAM)

        if not addr_info_list:
             log_msg(logging.ERROR, f"[ERROR][NET] getaddrinfo failed for {g_pool_host} (no results)")
             return None

        for res in addr_info_list:
            af, socktype, proto, canonname, sa = res
            try:
                log_msg(logging.INFO, f"[NET] Attempting connect to {g_pool_host} ({sa[0]}) port {sa[1]}...")
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(10)
                sock.connect(sa)
                sock.settimeout(None)
                log_msg(logging.INFO, f"[NET] Successfully connected to {g_pool_host}:{g_pool_port} via {sa[0]}")
                return sock

            except socket.error as e:
                log_msg(logging.WARNING, f"[WARN][NET] connect() to {sa[0]} failed: {e}")
                if sock:
                    sock.close()
                sock = None
                continue
            except Exception as e:
                log_msg(logging.ERROR, f"[ERROR][NET] Unexpected error during connect attempt: {e}")
                if sock:
                    sock.close()
                sock = None
                continue

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
        sock.sendall(msg.encode('utf-8'))
        return True
    except socket.error as e:
        log_msg(logging.ERROR, f"[ERROR][NET] sendall() failed on socket: {e}")
        g_connection_lost_event_mp.set()
        return False
    except (TypeError, json.JSONDecodeError) as e:
         log_msg(logging.ERROR, f"[ERROR][NET] Failed to encode JSON for sending: {e} - Data: {message_dict}")
         return False
    except Exception as e:
        log_msg(logging.ERROR, f"[ERROR][NET] Unexpected error sending JSON: {e}")
        g_connection_lost_event_mp.set()
        return False

# --- Miner Process Function ---
def miner_process_func(process_id, num_processes, job_q, submit_q, hash_q, shutdown_event, connection_lost_event, shared_target_mgr, shared_target_lock):
    """Main function for each miner process."""

    process_name = f"MinerProc-{process_id}"
    multiprocessing.current_process().name = process_name

    log_msg(logging.INFO, f"[MINER {process_id}] Process started.")

    # Process-local state variables
    current_job_dict = None
    extranonce2_size_local = 4
    extranonce2_bin_local = bytearray()

    # Local copy of share target
    local_share_target = 0
    share_target_loaded = False


    try: # Main try block for the process function

        # --- Main Mining Loop: Stay alive until shutdown or disconnect ---
        while not shutdown_event.is_set() and not connection_lost_event.is_set():

            # --- Wait for a new job ---
            # Reset job-specific state before waiting for a new job
            current_job_dict = None
            job_payload = None
            job_abandoned_by_process = False # Reset abandonment flag for a new job cycle

            try:
                # Block until a job is available, with timeout to check events periodically
                log_msg(logging.DEBUG, f"[MINER {process_id}] Waiting for job...")
                job_payload = job_q.get(block=True, timeout=0.5)
                current_job_dict = job_payload
                log_msg(logging.INFO, f"[MINER {process_id}] Got job {current_job_dict.get('job_id', 'N/A')}.")
                
                # --- Successfully got a job payload, process it ---
                # Extract job details from the payload dictionary
                current_job_id_local = current_job_dict.get('job_id')
                version_local_le = current_job_dict.get('version_le')
                prevhash_local_bin_le = current_job_dict.get('prevhash_bin_le')
                coinb1_local_bin = current_job_dict.get('coinb1_bin')
                coinb2_local_bin = current_job_dict.get('coinb2_bin')
                extranonce1_local_bin = current_job_dict.get('extranonce1_bin')
                merkle_branch_local_bin_be = current_job_dict.get('merkle_branch_bin_be', [])
                ntime_local_le = current_job_dict.get('ntime_le')
                nbits_local_le = current_job_dict.get('nbits_le')
                clean_job_flag = current_job_dict.get('clean_jobs', False)
                extranonce2_size_local = current_job_dict.get('extranonce2_size', 4)

                # Get current share target from shared memory (Manager object)
                with shared_target_lock:
                    target_val = shared_target_mgr.value
                    if isinstance(target_val, int) and target_val > 0:
                         local_share_target = target_val
                         share_target_loaded = True
                    else:
                         share_target_loaded = False
                         log_msg(logging.WARNING, f"[MINER {process_id}] Shared target not set or zero ({target_val}) for job {current_job_id_local}. Abandoning job.")
                         # No valid target, abandon this job immediately and wait for the next one
                         continue # Go back to the start of the outer while loop to wait for next job

                # Initialize extranonce2 for the new job based on process ID and size
                if not isinstance(extranonce2_size_local, int) or extranonce2_size_local <= 0:
                     log_msg(logging.ERROR, f"[MINER {process_id}] Invalid extranonce2_size received for job {current_job_id_local}: {extranonce2_size_local}. Abandoning job.")
                     continue # Go back to the start of the outer while loop

                extranonce2_bin_local = bytearray(extranonce2_size_local)
                if num_processes > 0:
                     start_val = process_id
                     max_start_val = (1 << (extranonce2_size_local * 8)) - 1
                     start_val = start_val % (max_start_val + 1) if max_start_val >= 0 else start_val

                     try:
                         for i in range(extranonce2_size_local):
                              extranonce2_bin_local[i] = (start_val >> (i * 8)) & 0xFF
                     except IndexError:
                         log_msg(logging.ERROR, f"[MINER {process_id}] E2 size mismatch during initialization. Abandoning job {current_job_id_local}.")
                         continue # Go back to the start of the outer while loop

                # Log job start details
                target_hex = f"{local_share_target:064x}" if share_target_loaded else "NotSet"
                log_msg(logging.INFO, f"[MINER {process_id}] Starting job {current_job_id_local} (Clean:{'Y' if clean_job_flag else 'N'} E2Size:{extranonce2_size_local} E2Start(LE):{bin_to_hex(extranonce2_bin_local)} NetNB:0x{nbits_local_le:08x} ShareTgt:{target_hex})")

                # Remember the starting E2 value for this slice for the wrap check
                initial_e2_value = bytes(extranonce2_bin_local)


                # --- Hashing Loop: Work on the current job slice (iterate Extranonce2 values) ---
                # This loop continues until job is abandoned or E2 space is exhausted for this process slice
                while not job_abandoned_by_process and not shutdown_event.is_set() and not connection_lost_event.is_set():

                    # Calculate current Merkle Root and Header Template outside the Nonce loop (per E2 value)
                    try:
                        current_merkle_root_le = calculate_simplified_merkle_root_le(
                            coinb1_local_bin, extranonce1_local_bin, extranonce2_bin_local,
                            coinb2_local_bin, merkle_branch_local_bin_be)
                        if not current_merkle_root_le or len(current_merkle_root_le) != 32:
                            log_msg(logging.ERROR, f"[MINER {process_id}] Failed to calculate merkle root for job {current_job_id_local} E2 {bin_to_hex(extranonce2_bin_local)}. Incrementing E2.")
                             # Error in Merkle calc, try next E2 slice
                            if not increment_extranonce2(extranonce2_bin_local):
                                 log_msg(logging.WARNING, f"[WARN][P{process_id}] E2 space wrapped after Merkle Root error for job {current_job_id_local}. Abandoning job.")
                                 job_abandoned_by_process = True
                            continue # Continue the outer E2 loop (either next E2 or break if job_abandoned)

                        header_template_le = struct.pack('<I', version_local_le) + \
                                             prevhash_local_bin_le + \
                                             current_merkle_root_le + \
                                             struct.pack('<I', ntime_local_le) + \
                                             struct.pack('<I', nbits_local_le)
                        if len(header_template_le) != 76:
                             log_msg(logging.ERROR, f"[MINER {process_id}] Header template length incorrect ({len(header_template_le)}) for job {current_job_id_local} E2 {bin_to_hex(extranonce2_bin_local)}. Incrementing E2.")
                             # Error in header template, try next E2 slice
                             if not increment_extranonce2(extranonce2_bin_local):
                                  log_msg(logging.WARNING, f"[WARN][P{process_id}] E2 space wrapped after Header template error for job {current_job_id_local}. Abandoning job.")
                                  job_abandoned_by_process = True
                             continue
                    except Exception as e:
                         log_msg(logging.ERROR, f"[MINER {process_id}] Exception preparing job data for E2 slice {bin_to_hex(extranonce2_bin_local)}: {e}. Incrementing E2.")
                         if not increment_extranonce2(extranonce2_bin_local):
                              log_msg(logging.WARNING, f"[WARN][P{process_id}] E2 space wrapped after prep exception for job {current_job_id_local}. Abandoning job.")
                              job_abandoned_by_process = True
                         continue


                    # --- Nonce Loop: Iterate through the Nonce space for the current E2 value ---
                    nonce_limit = 0xFFFFFFFF # 2^32 - 1
                    nonce_start = process_id # Distribute nonce space based on process ID
                    nonce_step = num_processes # Step by the total number of processes
                    # Adjust start/step in case of unusual num_processes or large process_id
                    nonce_start = nonce_start if nonce_start <= nonce_limit else 0
                    nonce_step = nonce_step if nonce_step > 0 else 1 # Prevent division by zero

                    hash_counter_batch = 0 # Count hashes in batches for reporting

                    for nonce_le_int in range(nonce_start, nonce_limit + 1, nonce_step):
                        # --- Periodic checks within the Nonce loop ---
                        # Check events/new job/target updates roughly every 65536 nonces processed by this process slice
                        if (nonce_le_int & 0xFFFF) == (process_id & 0xFFFF):
                             # Check for shutdown or connection lost event
                             if shutdown_event.is_set() or connection_lost_event.is_set():
                                log_msg(logging.INFO, f"[MINER {process_id}] Shutdown/Disconnect event detected during nonce loop.")
                                job_abandoned_by_process = True
                                break # Exit Nonce loop

                             # Check for new job signal (non-blocking)
                             try:
                                # Use get_nowait() to check if a new job has arrived without blocking
                                job_q.get_nowait()
                                log_msg(logging.INFO, f"[MINER {process_id}] New job available while working on {current_job_id_local}. Abandoning current nonce range.")
                                job_abandoned_by_process = True # Signal to abandon the current job
                                break # Exit Nonce loop
                             except Empty:
                                 pass # No new job available, continue mining

                             # Check for target updates (using shared memory)
                             with shared_target_lock:
                                 target_val = shared_target_mgr.value
                                 if not isinstance(target_val, int) or target_val <= 0:
                                     log_msg(logging.WARNING, f"[WARN][MINER {process_id}] Shared target became invalid/zero ({target_val}) mid-job {current_job_id_local}. Abandoning job.")
                                     job_abandoned_by_process = True # Signal abandonment
                                     # No need to increment E2 here, we are abandoning the whole job
                                     break # Exit Nonce loop
                                 elif share_target_loaded and target_val != local_share_target:
                                     log_msg(logging.INFO, f"[MINER {process_id}] Share target updated mid-job {current_job_id_local}. Applying.")
                                     local_share_target = target_val
                                     share_target_loaded = True

                             # Report hash count periodically (Aligned with periodic checks)
                             if hash_counter_batch > 0:
                                  try:
                                      hash_queue.put_nowait((process_id, hash_counter_batch))
                                  except Full:
                                      log_msg(logging.WARNING, f"[MINER {process_id}] Hash queue full, dropping batch count.")
                                  hash_counter_batch = 0 # Reset batch counter

                        # If job was abandoned by a check inside the periodic block (like new job or target invalid), break the loop
                        # This check should be *after* the periodic checks block and *before* the hashing logic.
                        # It needs to be indented to the same level as the 'if (nonce_le_int & 0xFFFF)' block.
                        if job_abandoned_by_process:
                            log_msg(logging.INFO, f"[MINER {process_id}] Job abandonment signal detected within nonce loop. Breaking.")
                            break # Exit Nonce loop

                        # --- Prepare 80-byte header with current nonce --- (Aligned with per-Nonce logic)
                        try:
                            nonce_le_bytes = struct.pack('<I', nonce_le_int)
                            header_le_80bytes = header_template_le + nonce_le_bytes
                            if len(header_le_80bytes) != 80:
                                 log_msg(logging.ERROR, f"[MINER {process_id}] Constructed header length != 80 ({len(header_le_80bytes)}) for nonce {nonce_le_int}. Skipping.")
                                 continue # Skip to next nonce
                        except struct.error:
                            log_msg(logging.WARNING, f"[MINER {process_id}] Failed to pack nonce {nonce_le_int}. Skipping.")
                            continue

                        # --- Double SHA256 Hashing --- (Aligned with per-Nonce logic)
                        try:
                            final_hash_be = sha256_double_be(header_le_80bytes)
                        except Exception as e:
                             log_msg(logging.ERROR, f"[MINER {process_id}] SHA256 hashing failed for nonce {nonce_le_int}: {e}. Incrementing E2.")
                             # Hashing error on this specific header, increment E2 to move on
                             if not increment_extranonce2(extranonce2_bin_local):
                                  log_msg(logging.WARNING, f"[WARN][P{process_id}] E2 space wrapped after hashing exception for job {current_job_dict.get('job_id')}. Abandoning job.")
                                  job_abandoned_by_process = True # Fully abandon job
                             break # Exit Nonce loop and continue outer E2 loop (which might break if job_abandoned)

                        hash_counter_batch += 1 # (Aligned with per-Nonce logic)
                        final_hash_le = final_hash_be[::-1] # (Aligned with per-Nonce logic)

                        # --- Check result against share target --- (Aligned with per-Nonce logic)
                        if share_target_loaded and is_hash_less_or_equal_target(final_hash_le, local_share_target):
                            # --- Share Found --- (Aligned with per-Nonce logic)
                            winning_nonce_le = nonce_le_int
                            hash_hex_be = bin_to_hex(final_hash_be)
                            share_timestamp = timestamp_us()

                            network_difficulty = calculate_difficulty_nbits(nbits_local_le)
                            share_difficulty = calculate_difficulty_from_target(int.from_bytes(final_hash_le, 'little'))
                            meets_network_target = (network_difficulty is not None and network_difficulty > 0 and share_difficulty is not None and share_difficulty >= network_difficulty)

                            print(f"\r{' '*80}\r", end='', file=sys.stderr)
                            print(f"{C_GREEN}[P{process_id} {share_timestamp}] Share found! Job: {current_job_id_local} Nonce: 0x{winning_nonce_le:08x} {'[BLOCK!]' if meets_network_target else ''}{C_RESET}", flush=True)

                            target_hex_log = f"{local_share_target:064x}" if local_share_target is not None else "NotSet"
                            log_msg(logging.INFO, f"[SHARE FOUND][P{process_id}] Job={current_job_id_local} N(LE)=0x{winning_nonce_le:08x} H(BE)={hash_hex_be} Tgt={target_hex_log} E2(LE)={bin_to_hex(extranonce2_bin_local)} {'[BLOCK!]' if meets_network_target else ''}")

                            # --- Submit Share (Send to main process via Queue) --- (Aligned with per-Nonce logic)
                            ntime_hex_be = uint32_to_hex_be(ntime_local_le)
                            nonce_hex_be = uint32_to_hex_be(winning_nonce_le)
                            extranonce2_hex = bin_to_hex(extranonce2_bin_local)

                            submit_payload = [
                                g_wallet_addr,
                                current_job_id_local,
                                extranonce2_hex,
                                ntime_hex_be,
                                nonce_hex_be
                            ]
                            try:
                                submit_queue.put(submit_payload, block=True, timeout=5)
                                log_msg(logging.INFO, f"[SUBMIT][P{process_id}] Sent share payload for job {current_job_id_local} to submit queue.")
                            except Full:
                                 log_msg(logging.WARNING, f"[SUBMIT][P{process_id}] Submit queue full, failed to submit share for job {current_job_id_local}. Dropping share.")
                            except Exception as e:
                                log_msg(logging.ERROR, f"[SUBMIT][P{process_id}] Failed to put share payload onto submit queue: {e}")

                            job_abandoned_by_process = True # Share found, stop working on this job slice
                            break # Exit nonce loop

                    # --- End Nonce Loop ---


                    # Report any remaining hashes from the loop (After Nonce loop finishes)
                    if hash_counter_batch > 0:
                        try:
                             hash_queue.put_nowait((process_id, hash_counter_batch))
                        except Full: pass
                        hash_counter_batch = 0

                    # If job was abandoned by a check inside the nonce loop (e.g., new job, target change, error, share found), break extranonce2 loop
                    # This check needs to be *after* the Nonce loop completes, deciding whether to increment E2 or break the E2 loop.
                    if job_abandoned_by_process:
                        log_msg(logging.INFO, f"[MINER {process_id}] Job abandoned while working on job {current_job_id_local}. Breaking E2 loop.")
                        break # Exit E2 loop and go back to waiting for a new job from the queue

                    # --- Increment Extranonce2 (Little Endian) ---
                    # This only happens if the nonce loop completed for the current E2 value without abandoning
                    if not increment_extranonce2(extranonce2_bin_local):
                        # Full wrap-around occurred for this process's extranonce2 slice
                        log_msg(logging.WARNING, f"[WARN][P{process_id}] Extranonce2 space fully wrapped for job {current_job_id_local}. E2(LE): {bin_to_hex(extranonce2_bin_local)}. Abandoning job slice.")
                        job_abandoned_by_process = True # Mark job as done for this process slice
                        break # Exit E2 loop

                    # Optional: Simple check if E2 returned to its *initial* value for this slice
                    # This isn't a perfect global exhaustion check but matches some miner logic
                    if extranonce2_size_local > 0 and bytes(extranonce2_bin_local) == initial_e2_value:
                       log_msg(logging.WARNING, f"[WARN][P{process_id}] Extranonce2 space slice potentially exhausted (returned to start value) for job {current_job_id_local}. Abandoning job slice.")
                       job_abandoned_by_process = True
                       break # Exit E2 loop


                # --- End Hashing Loop (over E2 values) ---
                # If we reach here, either the job was abandoned (job_abandoned_by_process=True) or E2 space wrapped.
                # The outer while loop will continue, and we will go back to the job_q.get() call
                # to wait for the *next* job.

            except Empty:
                # Timeout occurred while waiting for a job (job_q.get(timeout=0.5)).
                # Check events and continue waiting by letting the outer loop repeat. Correct behavior.
                log_msg(logging.DEBUG, f"[MINER {process_id}] Job queue timeout, checking events...")
                continue # Go back to the start of the outer while loop (which checks events again) and try job_q.get()

            except Exception as e:
                # Catch any unexpected exceptions that occur *after* successfully getting a job
                # but *before* or *during* initial processing of job parameters.
                log_msg(logging.ERROR, f"[FATAL][MINER {process_id}] Unhandled exception during job processing (Job ID: {current_job_dict.get('job_id', 'N/A')}): {e}")
                import traceback
                log_msg(logging.ERROR, traceback.format_exc())
                # Clear current_job_dict and abandon the current job to get a new one.
                current_job_dict = None
                job_abandoned_by_process = True # Ensure job is marked as abandoned due to error
                # The outer while loop continues, leading back to job_q.get() for the next job. Correct behavior.
                continue # Go back to the start of the outer while loop

        # --- End of Main Mining Loop (while not shutdown_event.is_set() ...) ---
        # This part is only reached when shutdown_event or connection_lost_event is set.

    except Exception as e:
        # Catch any unexpected exceptions that occur *outside* the main mining loop
        # (e.g., during initial setup or if the outer loop structure itself throws).
        log_msg(logging.FATAL, f"[FATAL][MINER {process_id}] Terminating due to unhandled exception outside main loop: {e}")
        import traceback
        log_msg(logging.FATAL, traceback.format_exc())
        # Process will now exit.

    log_msg(logging.INFO, f"[MINER {process_id}] Process finished.")

# --- End of miner_process_func ---


# --- Subscribe Thread Function ---
def subscribe_func(job_q, submit_q, shutdown_event, connection_lost_event, shared_target_mgr, shared_target_lock, height_lock):
    """Handles Stratum protocol communication. Runs as a thread in the main process."""
    global g_socket
    global g_current_height # Need to access and potentially update this global variable

    thread_name = "Subscribe"
    threading.current_thread().name = thread_name
    log_msg(logging.INFO, "[SUB] Subscribe thread started.")

    buffer_agg = ""
    last_e1_bin = b''
    last_e2_size = 4
    last_ph_hex = ""

    time.sleep(0.2)

    # Outer loop: Handles connection cycles
    while not shutdown_event.is_set():
        sock_to_use = None
        with g_socket_lock:
            sock_to_use = g_socket

        if sock_to_use is None:
           if connection_lost_event.is_set():
                log_msg(logging.DEBUG, "[SUB] Connection lost event detected, waiting for reconnect in main loop.")
                time.sleep(1)
           else:
                log_msg(logging.ERROR, "[SUB] Socket is None unexpectedly but connection_lost_event is not set. Waiting.")
                time.sleep(1)
           continue

        log_msg(logging.INFO, f"[SUB] Using socket FD {sock_to_use.fileno()} for pool communication.")
        time.sleep(0.5)

        try:
            # Reset subscribe-specific state on a new connection attempt
            last_e1_bin = b''
            last_e2_size = 4
            last_ph_hex = ""

            # Send subscribe (ID 1)
            subscribe_future_id = 1
            subscribed = send_json_message(sock_to_use, {"id": subscribe_future_id, "method": "mining.subscribe", "params": ["SimplePythonMiner/1.0"]})
            if not subscribed:
                log_msg(logging.ERROR, "[SUB] Send subscribe failed.")
                time.sleep(RECONNECT_DELAY_SECONDS)
                continue

            # Send authorize (ID 2)
            authorize_future_id = 2
            authed = send_json_message(sock_to_use, {"id": authorize_future_id, "method": "mining.authorize", "params": [g_wallet_addr, g_pool_password]})
            if not authed:
                log_msg(logging.ERROR, "[SUB] Send authorize failed.")
                time.sleep(RECONNECT_DELAY_SECONDS)
                continue

        except Exception as e:
             log_msg(logging.ERROR, f"[ERR][SUB] Error during initial pool communication (subscribe/authorize): {e}")
             connection_lost_event.set()
             time.sleep(RECONNECT_DELAY_SECONDS)
             continue

        buffer_agg = ""
        log_msg(logging.INFO, f"[SUB] Waiting for pool messages on FD {sock_to_use.fileno()}...")

        # Inner loop: Process messages while connected
        try:
            import select

            while not shutdown_event.is_set() and not connection_lost_event.is_set():
                 with g_socket_lock:
                     if g_socket != sock_to_use:
                         log_msg(logging.INFO, f"[SUB] Socket FD {sock_to_use.fileno()} changed externally. Exiting receive loop.")
                         break

                 try:
                      ready_to_read, _, _ = select.select([sock_to_use], [], [], 0.1)
                 except ValueError:
                      log_msg(logging.WARNING, f"[SUB] Socket FD {sock_to_use.fileno()} became invalid during select. Exiting receive loop.")
                      break
                 except Exception as e:
                      log_msg(logging.ERROR, f"[ERR][SUB] Unexpected error during select on FD {sock_to_use.fileno()}: {e}. Exiting receive loop.")
                      break

                 if not ready_to_read:
                      continue

                 try:
                    chunk = sock_to_use.recv(8192)
                    if not chunk:
                        log_msg(logging.INFO, f"[SUB] Pool disconnected FD {sock_to_use.fileno()} (read 0 bytes).")
                        raise socket.error("Pool closed connection")
                 except socket.timeout:
                      continue
                 except socket.error as e:
                     log_msg(logging.ERROR, f"[ERR][SUB] Socket error during recv on FD {sock_to_use.fileno()}: {e}")
                     raise socket.error(f"Socket recv error: {e}")

                 buffer_agg += chunk.decode('utf-8', errors='replace')

                 while '\n' in buffer_agg:
                     line, buffer_agg = buffer_agg.split('\n', 1)
                     line = line.strip()
                     if not line: continue

                     try:
                         message = json.loads(line)
                         # log_msg(logging.DEBUG, f"[DEBUG][SUB] Recv: {line}")
                     except json.JSONDecodeError:
                         log_msg(logging.ERROR, f"[ERROR][SUB] JSON parse error for line: {line[:200]}...")
                         continue

                     # Process the parsed message and update subscribe thread state
                     last_e1_bin, last_e2_size, last_ph_hex = process_pool_message(
                         message, line, job_q, submit_q, shared_target_mgr,
                         shared_target_lock, g_current_height_lock,
                         last_e1_bin, last_e2_size, last_ph_hex
                     )

        except socket.error as e:
            log_msg(logging.ERROR, f"[ERR][SUB] Socket error on FD {sock_to_use.fileno()}: {e}. Signaling connection lost.")
            connection_lost_event.set()
        except RuntimeError as e:
             log_msg(logging.FATAL, f"[FATAL][SUB] Critical error processing message: {e}. Signaling connection lost.")
             connection_lost_event.set()
        except Exception as e:
            log_msg(logging.ERROR, f"[FATAL][SUB] Unexpected error in receive loop: {e}")
            import traceback
            log_msg(logging.ERROR, traceback.format_exc())
            connection_lost_event.set()

        # After exiting inner loop
        if shutdown_event.is_set():
            log_msg(logging.INFO, "[SUB] Shutdown signal received, exiting.")
            break

        if not connection_lost_event.is_set():
            log_msg(logging.WARNING, "[SUB] Exited receive loop unexpectedly. Signaling connection lost.")
            connection_lost_event.set()

        log_msg(logging.INFO, "[SUB] Waiting briefly before checking connection state again.")
        time.sleep(0.5)

    log_msg(logging.INFO, "[SUB] Subscribe thread finished.")

# --- Process Pool Messages ---
def process_pool_message(message, original_line, job_q, submit_q, shared_target_mgr, shared_target_lock, height_lock, last_e1_bin, last_e2_size, last_ph_hex):
    """Parses pool messages and updates state/queues. Returns updated state (E1, E2 size, last_ph_hex)."""
    # This function runs in the Subscribe thread (in the main process).
    # FIX: Declare g_current_height as global to avoid 'cannot access local variable' error.
    global g_current_height

    msg_id = message.get('id')
    method = message.get('method')
    params = message.get('params')
    result = message.get('result')
    error = message.get('error')

    try:
        if msg_id is not None:
            if error:
                err_str = json.dumps(error)
                log_msg(logging.ERROR, f"[ERR][SUB] Pool error response ID {msg_id}: {err_str}")
                print(f"\r{' '*80}\r{C_RED}[{timestamp_us()}] Pool Error (ID {msg_id}): {err_str}{C_RESET}", file=sys.stderr, flush=True)
                if msg_id in (1, 2):
                     raise RuntimeError("Pool indicated critical failure (subscribe/authorize)")

            elif result is not None or method is None:
                if msg_id == 1:
                    if isinstance(result, list) and len(result) >= 2:
                        try:
                           # Find extranonce1 (hex string) and extranonce2_size (integer) in the result list
                           e1h_idx, e2s_idx = -1, -1
                           # Look for a hex string which is likely E1
                           for i, item in enumerate(result):
                               if isinstance(item, str) and len(item) % 2 == 0:
                                   try: binascii.unhexlify(item); e1h_idx = i; break
                                   except: pass
                           # Look for an integer which is likely E2 size
                           for i, item in enumerate(result):
                               if isinstance(item, int): e2s_idx = i; break

                           if e1h_idx != -1 and e2s_idx != -1:
                                e1h = result[e1h_idx]
                                e2s_i = result[e2s_idx]
                                e1b = hex_to_bin(e1h)
                                if e1b is not None:
                                    last_e1_bin = e1b
                                    last_e2_size = int(e2s_i)
                                    log_msg(logging.INFO, f"[SUB] Subscribe OK. E1: {e1h} ({len(last_e1_bin)}B), E2Size: {last_e2_size}")
                                    print(f"[POOL] Subscribe OK. Extranonce2 Size: {last_e2_size}", flush=True)
                                else:
                                     log_msg(logging.ERROR, f"[ERR][SUB] Failed to convert extranonce1 hex '{e1h}'")
                                     raise RuntimeError("Invalid extranonce1 from subscribe response")
                           else:
                               log_msg(logging.ERROR, f"[ERR][SUB] Could not find E1(hex) and E2Size(int) in subscribe result: {result}")
                               raise RuntimeError("Invalid subscribe response format")
                        except Exception as e:
                            log_msg(logging.ERROR, f"[ERR][SUB] Error processing subscribe result: {e} - Result: {result}")
                            raise RuntimeError(f"Error processing subscribe response: {e}")
                    else:
                        log_msg(logging.ERROR, f"[ERR][SUB] Invalid subscribe result structure: {result}")
                        raise RuntimeError("Invalid subscribe response structure")

                elif msg_id == 2:
                    auth_ok = bool(result)
                    log_msg(logging.INFO, f"[SUB] Authorization {'successful' if auth_ok else 'failed'}.")
                    if auth_ok:
                        print(f"{C_GREEN}[POOL] Authorization OK.{C_RESET}", flush=True)
                    else:
                         err_str = json.dumps(result)
                         print(f"\r{' '*80}\r{C_RED}[{timestamp_us()}] AUTHORIZATION FAILED! Result: {err_str}. Check wallet/password.{C_RESET}", file=sys.stderr, flush=True)
                         raise RuntimeError("Authorization failed via pool response")

                elif isinstance(msg_id, int):
                    share_accepted = bool(result)
                    if share_accepted:
                        log_msg(logging.INFO, f"[SUB] Share (ID {msg_id}) accepted by pool.")
                        print(f"{C_GREEN}[{timestamp_us()}] Share Accepted! (ID {msg_id}){C_RESET}", flush=True)
                    else:
                        res_str = json.dumps(result)
                        log_msg(logging.WARNING, f"[WARN][SUB] Share (ID {msg_id}) rejected by pool. Result: {res_str}")
                        print(f"\r{' '*80}\r{C_YELLOW}[{timestamp_us()}] Share Rejected? (ID {msg_id}) Result: {res_str}{C_RESET}", file=sys.stderr, flush=True)

            # else: Handle unexpected successful responses if needed


        elif method:
            if method == "mining.notify":
                if isinstance(params, list) and len(params) >= 9:
                    try:
                        job_id_str, ph_h, cb1_h, cb2_h, mb_hex_list, v_h, nb_h, nt_h, clean_j = params[:9]

                        tph_be = hex_to_bin(ph_h)
                        tcb1 = hex_to_bin(cb1_h)
                        tcb2 = hex_to_bin(cb2_h)
                        tmbl_be = [hex_to_bin(h) for h in mb_hex_list]

                        if tph_be is None or len(tph_be) != 32: raise ValueError(f"Bad prevhash hex '{ph_h}'")
                        if tcb1 is None: raise ValueError(f"Bad coinb1 hex '{cb1_h}'")
                        if tcb2 is None: raise ValueError(f"Bad coinb2 hex '{cb2_h}'")
                        if not all(isinstance(b, bytes) and len(b) == 32 for b in tmbl_be): raise ValueError(f"Bad merkle branch hex list")

                        t_v = int.from_bytes(hex_to_bin(v_h), 'big')
                        t_nb = int.from_bytes(hex_to_bin(nb_h), 'big')
                        t_nt = int.from_bytes(hex_to_bin(nt_h), 'big')

                        if last_e1_bin is None or last_e2_size is None or last_e2_size <= 0:
                            log_msg(logging.WARNING, f"[WARN][SUB] Received mining.notify for job {job_id_str} but E1/E2 size not set yet. Skipping job.")
                            return last_e1_bin, last_e2_size, last_ph_hex

                        job_payload_dict = {
                            'job_id': job_id_str,
                            'prevhash_bin_le': tph_be[::-1],
                            'coinb1_bin': tcb1,
                            'coinb2_bin': tcb2,
                            'merkle_branch_bin_be': tmbl_be,
                            'version_le': t_v,
                            'nbits_le': t_nb,
                            'ntime_le': t_nt,
                            'clean_jobs': bool(clean_j),
                            'extranonce1_bin': last_e1_bin,
                            'extranonce2_size': last_e2_size
                        }

                        current_ph_hex = ph_h
                        new_block = (current_ph_hex != last_ph_hex)
                        last_ph_hex = current_ph_hex

                        if new_block:
                            with height_lock:
                                if g_current_height > 0: # Only increment if we have a valid starting height
                                    g_current_height += 1
                                ch = g_current_height # Get local copy for logging

                            net_diff = calculate_difficulty_nbits(t_nb)

                            log_msg(logging.INFO, f"[JOB] New Block ~{ch if ch > 0 else '?'}. Job: {job_id_str} (Clean:{'Y' if bool(clean_j) else 'N'} NetDiff: {net_diff:.3e} nBits:0x{t_nb:08x})")
                            print(f"\r{' '*80}\r", end='', file=sys.stderr)
                            print(f"{C_YELLOW}[*] New Block ~{ch if ch>0 else '?'} | NetDiff: {net_diff:.3e} | Job: {job_id_str}{C_RESET}", flush=True)
                        else:
                            log_msg(logging.INFO, f"[JOB] New Job: {job_id_str} (Clean:{'Y' if bool(clean_j) else 'N'})")

                        try:
                            # Replace any existing job in the queue (size 1) or put it if empty
                            # First, try clearing the queue non-blockingly to discard old job if any
                            try: job_q.get_nowait()
                            except Empty: pass # Queue was already empty

                            job_q.put(job_payload_dict, block=True, timeout=1) # Put new job, block briefly if needed
                        except Full:
                            log_msg(logging.WARNING, f"[WARN][SUB] Job queue full (max size 1), miner process not ready for new job? Skipping job {job_id_str}.")
                        except Exception as e:
                             log_msg(logging.ERROR, f"[ERR][SUB] Error putting job {job_id_str} onto queue: {e}")


                    except (ValueError, TypeError, IndexError, struct.error) as e:
                         log_msg(logging.ERROR, f"[ERR][SUB] mining.notify has bad params: {e}. Line: {original_line[:200]}...")
                    except Exception as e:
                         log_msg(logging.ERROR, f"[ERR][SUB] Unexpected error processing mining.notify: {e}. Line: {original_line[:200]}...")
                         import traceback
                         log_msg(logging.ERROR, traceback.format_exc()) # Log traceback for unexpected errors

                else:
                     log_msg(logging.WARNING, f"[WARN][SUB] Bad notify params structure. Params: {params}")

            elif method == "mining.set_difficulty":
                if isinstance(params, list) and len(params) > 0:
                    pool_difficulty = params[0]
                    if isinstance(pool_difficulty, (int, float)) and pool_difficulty > 0:
                        log_msg(logging.INFO, f"[SUB] Received pool difficulty: {pool_difficulty:.5f}")
                        print(f"[POOL] Difficulty set to: {pool_difficulty:.5f}", flush=True)
                        try:
                            if float(pool_difficulty) <= 0: raise ValueError("Difficulty must be positive")
                            new_target_f = float(TARGET1) / float(pool_difficulty)
                            new_target_int = max(1, min(int(new_target_f), MAX_TARGET_256))

                            with shared_target_lock:
                                if shared_target_mgr is not None:
                                    shared_target_mgr.value = new_target_int
                                else:
                                    log_msg(logging.ERROR, "[ERR][SUB] shared_target_mgr is None during set_difficulty. Cannot update target.")

                            current_share_target_value = None
                            with shared_target_lock:
                                if shared_target_mgr is not None:
                                    current_share_target_value = shared_target_mgr.value

                            actual_share_diff_btc_ref = calculate_difficulty_from_target(current_share_target_value)
                            target_hex_log = f"{current_share_target_value:064x}" if current_share_target_value is not None else "NotSet"
                            log_msg(logging.INFO, f"[SUB] Updated Share Target {target_hex_log}. PoolDiff: {pool_difficulty:.5f} -> ShareDiff(Ref): {actual_share_diff_btc_ref:.5f}")

                        except Exception as e:
                             log_msg(logging.ERROR, f"[ERR][SUB] Error calculating or setting share target: {e}")
                    else:
                        log_msg(logging.WARNING, f"[WARN][SUB] Difficulty has invalid type/value: {pool_difficulty}. Ignoring.")
                        print(f"[POOL] Difficulty invalid: {pool_difficulty} (Ignored)", flush=True)
                else:
                     log_msg(logging.WARNING, f"[WARN][SUB] Bad set_difficulty params structure. Params: {params}")
            else:
                log_msg(logging.WARNING, f"[WARN][SUB] Received unknown notification: {method}, Params: {params}")
        else:
             log_msg(logging.WARNING, f"[WARN][SUB] Received message with no ID/method: {original_line[:200]}...")

    except RuntimeError:
        raise
    except Exception as e:
        log_msg(logging.ERROR, f"[ERROR][SUB] Exception processing message: {e}. Line: {original_line[:200]}...")
        import traceback
        log_msg(logging.ERROR, traceback.format_exc())

    return last_e1_bin, last_e2_size, last_ph_hex

# --- Periodic Status Logger ---
def log_periodic_status():
    """Aggregates hash counts from miner processes and logs status."""
    global g_total_hashes_reported, g_aggregated_hash_rate, g_last_aggregated_report_time
    global g_process_hash_counts
    global shared_target

    now = time.monotonic()
    duration = now - g_last_aggregated_report_time

    if duration < 0.1: return

    try:
        while True:
            proc_id, count = hash_queue.get_nowait()
            g_process_hash_counts[proc_id] = g_process_hash_counts.get(proc_id, 0) + count
    except Empty:
        pass
    except Exception as e:
         log_msg(logging.ERROR, f"[STATUS] Error collecting hash counts from queue: {e}")

    current_total_hashes = sum(g_process_hash_counts.values())

    delta_hashes = current_total_hashes - g_total_hashes_reported
    if delta_hashes < 0 or duration > (STATUS_LOG_INTERVAL_SECONDS * 2):
         log_msg(logging.WARNING, "[STATUS] Hash count reset detected or large time jump. Resetting total hashes reported.")
         g_total_hashes_reported = current_total_hashes
         delta_hashes = 0

    current_rate = (delta_hashes / duration) if duration > 0 else 0.0

    g_aggregated_hash_rate = current_rate
    g_total_hashes_reported = current_total_hashes
    g_last_aggregated_report_time = now

    with g_current_height_lock: height_local = g_current_height

    share_target_val_for_status = None
    with shared_target_lock:
        if shared_target is not None and isinstance(shared_target.value, int):
            share_target_val_for_status = shared_target.value

    difficulty_share_local = calculate_difficulty_from_target(share_target_val_for_status)

    display_rate = current_rate
    rate_unit = "H/s"
    if display_rate >= 1e12: display_rate /= 1e12; rate_unit = "TH/s"
    elif display_rate >= 1e9: display_rate /= 1e9; rate_unit = "GH/s"
    elif display_rate >= 1e6: display_rate /= 1e6; rate_unit = "MH/s"
    elif display_rate >= 1e3: display_rate /= 1e3; rate_unit = "kH/s"

    log_msg(logging.INFO, f"[STATUS] Height: ~{height_local if height_local>0 else '?'} | ShareDiff: {difficulty_share_local:.3f} | Rate: {display_rate:.2f} {rate_unit}")

    status_line = f"[{timestamp_us()}] [STATUS] H: ~{height_local if height_local>0 else '?'} | ShareD: {difficulty_share_local:.3f} | Rate: {display_rate:.2f} {rate_unit}"
    print(f"\r{' '*80}\r{C_CYAN}{status_line}{C_RESET}", end='', file=sys.stderr)
    sys.stderr.flush()

# --- Share Submission Handler ---
def handle_share_submission(sock):
    """Checks the submit queue and sends shares to the pool if socket is available. Returns True if a share was processed."""
    if not sock:
        return False

    try:
        # Get a share submission payload without blocking
        submit_payload = submit_queue.get_nowait()

        submit_id = int(time.time() * 1000) + random.randint(0, 999)
        payload_dict = {
            "id": submit_id,
            "method": "mining.submit",
            "params": submit_payload
        }

        log_msg(logging.INFO, f"[MAIN] Sending share submission ID {submit_id} for job {submit_payload[1]}...")

        success = False
        with g_socket_lock:
             if g_socket == sock and g_socket is not None:
                 success = send_json_message(g_socket, payload_dict)
             else:
                 log_msg(logging.WARNING, f"[MAIN] Socket changed while trying to submit ID {submit_id}. Dropping share.")

        return True # Indicate that we *tried* to process a share from the queue

    except Empty:
        return False # Indicate no share was available to process
    except Exception as e:
        log_msg(logging.ERROR, f"[ERROR][MAIN] Exception handling share submission: {e}")
        return False # Indicate an error occurred during processing

# --- Main Function ---
def main():
    """Main entry point for the miner."""
    global g_socket
    global g_processes
    global g_process_hash_counts
    global g_total_hashes_reported, g_aggregated_hash_rate, g_last_aggregated_report_time
    global g_current_height
    global shared_target, shared_target_lock

    signal.signal(signal.SIGINT, handle_sigint)
    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    print(f"Loading configuration from {CONFIG_FILE}...")
    if not load_config():
        sys.exit(1)

    setup_file_logger()

    log_msg(logging.INFO,"--------------------------------------------------")
    log_msg(logging.INFO,"Miner starting with configuration:")
    log_msg(logging.INFO,f"  Pool: {g_pool_host}:{g_pool_port}")
    log_msg(logging.INFO,f"  Wallet/Worker: {g_wallet_addr}")
    log_msg(logging.INFO,f"  Password: {'[empty]' if not g_pool_password else '(set)'}")
    log_msg(logging.INFO,f"  Processes: {g_processes}")
    log_msg(logging.INFO,f"  Log File: {g_log_file}")
    log_msg(logging.INFO,"--------------------------------------------------")

    print(f"{C_MAG}--- Simple Python Miner (SHA256d) ---{C_RESET}")
    print(f"{C_MAG}----------------------------------------{C_RESET}")
    print(f"{C_MAG} Wallet: {C_YELLOW}{g_wallet_addr}{C_RESET}")
    print(f"{C_MAG} Processes: {C_YELLOW}{g_processes}{C_RESET}")
    print(f"{C_MAG} Pool: {C_YELLOW}{g_pool_host}:{g_pool_port}{C_RESET}")
    print(f"{C_MAG}----------------------------------------{C_RESET}")
    sys.stdout.flush()

    manager = multiprocessing.Manager()
    log_msg(logging.INFO, "[MAIN] Created multiprocessing Manager.")

    shared_target_mgr = manager.Value('object', TARGET1)
    shared_target = shared_target_mgr
    log_msg(logging.INFO, "[MAIN] Initialized shared_target via Manager with TARGET1.")

    log_msg(logging.INFO,"[MAIN] Fetching initial block height...")
    print("[INFO] Fetching initial block height from API...")
    sys.stdout.flush()
    initial_height = get_current_block_height()
    with g_current_height_lock:
        g_current_height = initial_height
    if initial_height > 0:
        print(f"{C_CYAN}[INFO] Initial block height estimated at: {initial_height}{C_RESET}")
        log_msg(logging.INFO, f"[MAIN] Initial block height from API: {initial_height}")
    else:
        print(f"{C_YELLOW}[WARN] Could not fetch initial block height from API.{C_RESET}")
        log_msg(logging.WARNING, "[WARN] Failed to fetch initial block height from API.")
    sys.stdout.flush()

    height_check_interval = 15 * 60
    last_height_check_time = time.monotonic()
    status_log_interval = STATUS_LOG_INTERVAL_SECONDS
    last_status_log_time = time.monotonic()

    miner_processes = []
    sub_thread = None

    while not g_shutdown_event_mp.is_set():
        log_msg(logging.INFO, f"[MAIN] Attempting connection to pool {g_pool_host}:{g_pool_port}...")
        print(f"[NET] Connecting to {g_pool_host}:{g_pool_port}...")
        sys.stdout.flush()

        g_connection_lost_event_mp.clear()

        new_socket = connect_pool()

        if new_socket is None:
            log_msg(logging.WARNING, f"[MAIN] Connection failed. Retrying in {RECONNECT_DELAY_SECONDS} seconds...")
            print(f"\r{' '*80}\r{C_YELLOW}[NET] Connection failed. Retrying in {RECONNECT_DELAY_SECONDS} seconds...{C_RESET}", file=sys.stderr)
            sys.stderr.flush()
            g_shutdown_event_mp.wait(timeout=RECONNECT_DELAY_SECONDS)
            if g_shutdown_event_mp.is_set(): break
            continue

        with g_socket_lock:
             g_socket = new_socket
        log_msg(logging.INFO, f"[MAIN] Connection successful (FD: {g_socket.fileno()}). Starting processes...")
        print(f"{C_GREEN}[NET] Connected! Starting {g_processes} miner processes.{C_RESET}")
        sys.stdout.flush()

        # Clear IPC queues to discard stale data
        log_msg(logging.INFO, "[MAIN] Clearing IPC queues for new connection.")
        try:
            while True: job_queue.get_nowait()
        except Empty: pass
        except Exception as e: log_msg(logging.ERROR, f"[MAIN] Error draining job queue: {e}")
        try:
            while True: submit_queue.get_nowait()
        except Empty: pass
        except Exception as e: log_msg(logging.ERROR, f"[MAIN] Error draining submit queue: {e}")
        try:
            while True: hash_queue.get_nowait()
        except Empty: pass
        except Exception as e: log_msg(logging.ERROR, f"[MAIN] Error draining hash queue: {e}")


        with shared_target_lock:
            shared_target_mgr.value = TARGET1
            log_msg(logging.INFO, "[MAIN] Reset shared_target_mgr value to Difficulty 1 scale.")

        g_process_hash_counts = {}
        g_total_hashes_reported = 0
        g_aggregated_hash_rate = 0.0
        g_last_aggregated_report_time = time.monotonic()


        sub_thread = threading.Thread(
            target=subscribe_func,
            args=(job_queue, submit_queue, g_shutdown_event_mp, g_connection_lost_event_mp, shared_target_mgr, shared_target_lock, g_current_height_lock),
            name="Subscribe", daemon=True)
        sub_thread.start()

        miner_processes = []
        for i in range(g_processes):
            miner_proc = multiprocessing.Process(
                target=miner_process_func,
                args=(i, g_processes, job_queue, submit_queue, hash_queue, g_shutdown_event_mp, g_connection_lost_event_mp, shared_target_mgr, shared_target_lock),
                name=f"MinerProc-{i}")
            miner_processes.append(miner_proc)
            g_process_hash_counts[i] = 0
            miner_proc.start()

        log_msg(logging.INFO, "[MAIN] Entering monitoring loop.")
        current_socket_for_submit = g_socket

        while not g_shutdown_event_mp.is_set() and not g_connection_lost_event_mp.is_set():

            shares_processed_this_tick = 0
            while handle_share_submission(current_socket_for_submit):
                 shares_processed_this_tick += 1
                 if shares_processed_this_tick > 10:
                     break

            now_monotonic = time.monotonic()
            if now_monotonic - last_status_log_time >= status_log_interval:
                try:
                    log_periodic_status()
                except Exception as e:
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
                            g_current_height = external_height
                        elif external_height < local_height and local_height > 0:
                            log_msg(logging.WARNING, f"[WARN][MAIN] External height {external_height} < local height {local_height}. Ignoring minor discrepancy.")
                else:
                    log_msg(logging.WARNING, "[WARN][MAIN] Periodic external height check failed.")
                last_height_check_time = now_monotonic

            # Sleep briefly only if no shares were processed, to avoid busy-waiting
            if shares_processed_this_tick == 0:
                 time.sleep(0.01)


        # --- End Monitor Loop ---

        # --- Disconnection or Shutdown Detected ---
        if g_shutdown_event_mp.is_set():
             log_msg(logging.INFO, "[MAIN] Shutdown requested. Stopping processes...")
        elif g_connection_lost_event_mp.is_set():
             log_msg(logging.INFO, "[MAIN] Connection lost detected. Stopping processes and preparing to reconnect...")
             ts = timestamp_us()
             print(f"\r{' '*80}\r{C_YELLOW}[{ts}] Pool connection lost. Reconnecting...{C_RESET}", file=sys.stderr, flush=True)

        g_connection_lost_event_mp.set()
        g_shutdown_event_mp.set()

        closed_socket_fd = -1
        with g_socket_lock:
             if g_socket:
                 closed_socket_fd = g_socket.fileno()
                 try: g_socket.shutdown(socket.SHUT_RDWR)
                 except socket.error: pass
                 try:
                     g_socket.close()
                     log_msg(logging.INFO, f"[MAIN] Closed socket FD {closed_socket_fd}.")
                 except socket.error as e:
                     log_msg(logging.WARNING, f"[MAIN] Error closing socket FD {closed_socket_fd}: {e}")
                 g_socket = None
        current_socket_for_submit = None

        log_msg(logging.INFO, f"[MAIN] Joining {len(miner_processes)} miner processes...")
        join_timeout_per_proc = 5.0
        start_join = time.monotonic()
        joined_count = 0

        for proc in miner_processes:
             remaining_timeout = max(0.1, (start_join + join_timeout_per_proc * g_processes) - time.monotonic())
             remaining_procs_to_join = len(miner_processes) - joined_count
             proc_join_timeout = remaining_timeout / remaining_procs_to_join if remaining_procs_to_join > 0 else 0.1

             proc.join(timeout=proc_join_timeout)

             if proc.is_alive():
                 log_msg(logging.WARNING, f"[MAIN] Process {proc.name} did not join within timeout ({proc_join_timeout:.2f}s). Terminating.")
                 try:
                      proc.terminate()
                      proc.join(timeout=2.0)
                      if proc.is_alive():
                           log_msg(logging.ERROR, f"[MAIN] Process {proc.name} did not terminate after terminate().")
                      else:
                           log_msg(logging.INFO, f"[MAIN] Process {proc.name} terminated.")
                 except Exception as e:
                      log_msg(logging.ERROR, f"[MAIN] Error terminating process {proc.name}: {e}")
             else:
                 log_msg(logging.INFO, f"[MAIN] Process {proc.name} joined.")
                 joined_count += 1
        miner_processes.clear()
        log_msg(logging.INFO, f"[MAIN] Joined {joined_count}/{g_processes} miner processes.")


        if sub_thread and sub_thread.is_alive():
             log_msg(logging.INFO, "[MAIN] Joining subscribe thread...")
             sub_thread.join(timeout=5.0)
             if sub_thread.is_alive():
                  log_msg(logging.WARNING, "[MAIN] Subscribe thread did not join within timeout.")
             else:
                  log_msg(logging.INFO, "[MAIN] Subscribe thread joined.")

        if g_shutdown_event_mp.is_set():
             log_msg(logging.INFO, "[MAIN] Shutdown confirmed. Exiting main loop.")
             break
        else:
             log_msg(logging.INFO, f"[MAIN] Waiting {RECONNECT_DELAY_SECONDS}s before attempting reconnect...")
             g_shutdown_event_mp.wait(timeout=RECONNECT_DELAY_SECONDS)
             if g_shutdown_event_mp.is_set(): break

    # --- End Main Reconnect Loop ---

    log_msg(logging.INFO, "[MAIN] Miner shutting down cleanly.")
    print(f"\n{C_GREEN}Miner exiting...{C_RESET}")
    sys.stdout.flush()

    try: log_periodic_status()
    except Exception as e: log_msg(logging.ERROR, f"[ERROR][STATUS] Error during final status log: {e}")

    if 'manager' in locals() and manager:
        try:
            manager.shutdown()
            log_msg(logging.INFO, "[MAIN] Multiprocessing Manager shut down.")
        except Exception as e:
            log_msg(logging.ERROR, f"[MAIN] Error shutting down Manager: {e}")

    if file_handler:
        try:
            file_handler.close()
        except Exception as e:
             print(f"{C_YELLOW}[WARN] Error closing log file handler: {e}{C_RESET}", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
