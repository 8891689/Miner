#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author：8891689 ,https://github.com/8891689
# Assist in creation：gemini
import socket
import json
import time
import threading # Still used for the subscribe thread (I/O bound)
import multiprocessing # Used for CPU-bound miner processes
import multiprocessing # Manager is accessed via multiprocessing.Manager()
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
from queue import Queue, Empty, Full # Import Full for checking queue full

### DOGE CHANGE ###
# Import the scrypt library
try:
    import scrypt # pip install scrypt
except ImportError:
    print("Error: 'scrypt' library not found. Please install it using: pip install scrypt")
    sys.exit(1)
# ----------------- #

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
g_log_file = "doge_miner.log"
g_processes = 0 # Number of mining processes

CONFIG_FILE = "config_doge.json"
RECONNECT_DELAY_SECONDS = 5
STATUS_LOG_INTERVAL_SECONDS = 30

# ANSI colors for console output
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
job_queue = multiprocessing.Queue(maxsize=1) # Small size to backpressure job producer if needed
submit_queue = multiprocessing.Queue() # Shares found by processes
hash_queue = multiprocessing.Queue() # Hash counts from processes

# Shared memory and lock for state shared between main process and miner processes
# Use Manager for sharing arbitrary Python objects (like large integers for target)
# shared_target will be created via Manager in main()
shared_target = None # Placeholder
shared_target_lock = multiprocessing.Lock() # Lock still needed for Manager objects


# Global state for main process/subscribe thread
g_socket = None
g_socket_lock = threading.Lock() # Protect access to g_socket

g_current_height = -1
g_current_height_lock = threading.Lock() # Protect g_current_height

# Hashrate Calculation State (Aggregated in Main Process)
g_process_hash_counts = {} # {process_id: count}
g_total_hashes_reported = 0
g_aggregated_hash_rate = 0.0
g_last_aggregated_report_time = time.monotonic()


# --- Constants ---
# Bitcoin reference Difficulty 1 target
TARGET1_BTC_REF = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
# Scrypt Difficulty 1 target scale factor (approx.)
TARGET1_SCRYPT_SCALE = (0xFFFF << 208) # This value is a large Python integer
MAX_TARGET_256 = (1 << 256) - 1

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
        file_handler = logging.FileHandler(g_log_file, mode='a')
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.INFO)
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
    return second_hash

def calculate_simplified_merkle_root_le(
    coinb1_bin_param, extranonce1_bin_param,
    extranonce2_bin_param, coinb2_bin_param,
    merkle_branch_be_list_param):
    """Calculates the Merkle Root (LE) from components."""
    coinbase_tx_bin = (
        coinb1_bin_param +
        extranonce1_bin_param +
        extranonce2_bin_param +
        coinb2_bin_param
    )
    current_hash_be = sha256_double_be(coinbase_tx_bin)
    for branch_hash_be in merkle_branch_be_list_param:
        concat_be = current_hash_be + branch_hash_be
        current_hash_be = sha256_double_be(concat_be)
    merkle_root_le = current_hash_be[::-1]
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

def calculate_difficulty_nbits(nbits_le_int):
    """Calculates difficulty from nBits (Little Endian integer) vs BTC Target1."""
    if nbits_le_int == 0: return 0.0
    try:
        nbits_be_bytes = struct.pack('>I', nbits_le_int)
        nbits_be_parsed = struct.unpack('>I', nbits_be_bytes)[0]
    except struct.error:
        return 0.0

    exponent = (nbits_be_parsed >> 24) & 0xFF
    coefficient = nbits_be_parsed & 0x00FFFFFF

    if coefficient == 0: return float('inf')
    if exponent < 3 or exponent > 32: return 0.0

    try:
        target = coefficient * (2**(8 * (exponent - 3)))
        if target == 0: return float('inf')
        difficulty = float(TARGET1_BTC_REF) / float(target)
        return difficulty
    except OverflowError:
        try:
             diff1_coeff = 0x00ffff
             diff1_exp = 0x1d # 29
             diff1_exp_shift = 8 * (diff1_exp - 3)
             current_exp_shift = 8 * (exponent - 3)
             difficulty = (float(diff1_coeff) / float(coefficient)) * math.pow(2.0, diff1_exp_shift - current_exp_shift)
             return difficulty
        except (OverflowError, ValueError):
             return float('inf')
    except Exception:
        return 0.0


def calculate_difficulty_from_target(target_int):
    """Calculates difficulty from a 256-bit integer target, using BTC TARGET1 for reference."""
    if target_int is None or target_int <= 0:
        return float('inf')
    try:
        difficulty = float(TARGET1_BTC_REF) / float(target_int)
        return difficulty
    except OverflowError:
        return float('inf')
    except Exception:
        return 0.0

def uint32_to_hex_be(val_le_int):
    """Convert uint32_t (Little Endian host int) to Big Endian hex string."""
    try:
        be_int = struct.unpack('>I', struct.pack('<I', val_le_int))[0]
        return f"{be_int:08x}"
    except struct.error:
        return "00000000"

def increment_extranonce2(enonce2_bytearray):
    """Increments the extranonce2 bytearray (Little Endian)."""
    if not enonce2_bytearray:
        return False

    size = len(enonce2_bytearray)
    for i in range(size):
        if enonce2_bytearray[i] == 0xff:
            enonce2_bytearray[i] = 0
        else:
            enonce2_bytearray[i] += 1
            return True
    return False

# --- Config Loading ---
def load_config():
    """Loads configuration from JSON file."""
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
                    "pool_host": "stratum+tcp://pool.example.com",
                    "pool_port": 3333,
                    "wallet_address": "YOUR_DOGE_WALLET_ADDRESS.WorkerName",
                    "processes": 4,
                    "pool_password": "x",
                    "log_file": "doge_miner.log"
                }
                json.dump(example_json, f_example, indent=2)
            print(f"[INFO] Created example config file '{CONFIG_FILE}'. Please edit it.", file=sys.stderr)
        except Exception as e:
            print(f"{C_RED}[ERROR] Could not create example config file: {e}{C_RESET}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"{C_RED}[ERROR] Failed to read config file: {e}{C_RESET}", file=sys.stderr)
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
        if not isinstance(g_wallet_addr, str) or not g_wallet_addr or "YOUR_DOGE_WALLET_ADDRESS" in g_wallet_addr:
            error_field = "wallet_address"
            raise ValueError()

        g_processes = config.get("processes")
        if not isinstance(g_processes, int) or g_processes <= 0:
            error_field = "processes (must be a positive integer)"
            raise ValueError()

        g_pool_password = config.get("pool_password", "x")
        if not isinstance(g_pool_password, str):
            error_field = "pool_password"
            raise ValueError()

        g_log_file = config.get("log_file", "doge_miner.log")
        if not isinstance(g_log_file, str) or not g_log_file:
            g_log_file = "doge_miner.log"

    except ValueError:
        print(f"{C_RED}[ERROR] Invalid or missing configuration in '{CONFIG_FILE}': Check field '{error_field}'.{C_RESET}", file=sys.stderr)
        return False
    except Exception as e:
         print(f"{C_RED}[ERROR] Unexpected error loading config: {e}{C_RESET}", file=sys.stderr)
         return False

    print(f"[CONFIG] Configuration successfully loaded from {CONFIG_FILE}")
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

def get_current_block_height():
    """Fetches current block height from a Dogecoin API."""
    url = "https://api.blockchair.com/dogecoin/stats"
    headers = {'User-Agent': 'SimplePythonDogeMiner/1.0'}
    try:
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()
        data = response.json()
        if 'data' in data and isinstance(data['data'], dict) and 'blocks' in data['data']:
            height = int(data['data']['blocks'])
            if height > 0:
                return height
    except Exception as e:
        log_msg(logging.ERROR, f"[HTTP] Failed to get Dogecoin block height from {url}: {e}")
    return -1

def connect_pool():
    """Tries to connect to the pool. Returns socket object or None."""
    log_msg(logging.INFO, f"[NET] Resolving {g_pool_host}:{g_pool_port}...")
    sock = None
    try:
        addr_info_list = socket.getaddrinfo(g_pool_host, g_pool_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info_list:
             log_msg(logging.ERROR, f"[ERROR][NET] getaddrinfo failed for {g_pool_host}")
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
                if sock: sock.close()
                sock = None
                continue
            except Exception as e:
                log_msg(logging.ERROR, f"[ERROR][NET] Unexpected error during connect attempt: {e}")
                if sock: sock.close()
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

    current_job_dict = None
    extranonce2_size_local = 4
    extranonce2_bin_local = bytearray()
    local_share_target = 0
    share_target_loaded = False

    try:
        while not shutdown_event.is_set():

            # Wait for a new job payload
            job_payload = None
            try:
                # Block until a job is available, with timeout to check events
                job_payload = job_q.get(timeout=0.5)
                current_job_dict = job_payload

                # Extract job details from payload
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
                    # shared_target_mgr is the Manager.Value object
                    target_val = shared_target_mgr.value
                    if target_val is not None and target_val > 0:
                         local_share_target = target_val
                         share_target_loaded = True
                    else:
                         share_target_loaded = False
                         log_msg(logging.WARNING, f"[MINER {process_id}] Shared target not set or zero for job {current_job_id_local}. Skipping.")
                         current_job_dict = None # Invalidate job for this loop iteration
                         continue

                # Initialize extranonce2 based on process ID
                extranonce2_bin_local = bytearray(extranonce2_size_local)
                if extranonce2_size_local > 0 and num_processes > 0:
                     start_val = process_id
                     # Be cautious with large start_val vs E2 size
                     max_start_val = (1 << (extranonce2_size_local * 8)) - 1
                     # Prevent int overflow if start_val is huge, although process_id should be small
                     if start_val > max_start_val:
                          start_val = start_val % (max_start_val + 1) if max_start_val > 0 else 0
                          # log_msg(logging.DEBUG, f"[MINER {process_id}] Warning: Process ID larger than max E2 value, using modulo start: {start_val}")


                     try:
                         # Distribute the starting point bytes based on start_val
                         for i in range(extranonce2_size_local):
                              extranonce2_bin_local[i] = (start_val >> (i * 8)) & 0xFF
                     except IndexError:
                         log_msg(logging.ERROR, f"[MINER {process_id}] E2 size {extranonce2_size_local} too small for process distribution logic.")
                         current_job_dict = None
                         continue

                target_hex = f"{local_share_target:064x}" if share_target_loaded and local_share_target is not None else "NotSet"
                log_msg(logging.INFO, f"[MINER {process_id}] Starting job {current_job_id_local} (Clean:{'Y' if clean_job_flag else 'N'} E2Size:{extranonce2_size_local} E2Start(LE):{bin_to_hex(extranonce2_bin_local)} ShareTgt:{target_hex})")

            except Empty:
                # Timeout occurred while waiting for a job, check events
                if shutdown_event.is_set() or connection_lost_event.is_set():
                    break # Exit main while loop
                continue # No job yet, loop back to wait
            except Exception as e:
                log_msg(logging.ERROR, f"[FATAL][MINER {process_id}] Error receiving or processing job payload: {e}. Waiting for new job.")
                import traceback
                log_msg(logging.ERROR, traceback.format_exc())
                current_job_dict = None
                continue # Go back to wait for a new job

            # --- Hashing Loop ---
            job_abandoned_by_process = False
            initial_e2_value = bytes(extranonce2_bin_local)

            while not job_abandoned_by_process and not shutdown_event.is_set() and not connection_lost_event.is_set():

                # Periodically check events/target
                # Check events/target updates less frequently inside tight hash loops
                if random.randint(0, 50) == 0:
                    if shutdown_event.is_set() or connection_lost_event.is_set():
                        job_abandoned_by_process = True
                        break
                    # Check for new job signal (by trying to get from queue non-blockingly)
                    try:
                        job_q.get_nowait() # If successful, a new job is available
                        log_msg(logging.INFO, f"[MINER {process_id}] New job available. Abandoning old job {current_job_id_local}.")
                        job_abandoned_by_process = True
                        break # Exit E2 loop
                    except Empty:
                        pass # No new job, continue

                    # Check for target updates (using shared memory)
                    with shared_target_lock:
                         target_val = shared_target_mgr.value
                         if target_val is None or target_val <= 0:
                             log_msg(logging.WARNING, f"[WARN][MINER {process_id}] Shared target became zero mid-job {current_job_id_local}. Abandoning work.")
                             share_target_loaded = False
                             job_abandoned_by_process = True
                             break
                         elif share_target_loaded and target_val != local_share_target:
                             log_msg(logging.INFO, f"[MINER {process_id}] Share target updated mid-job {current_job_id_local}. Applying.")
                             local_share_target = target_val
                             # Continue with new target

                if job_abandoned_by_process: break # Check after periodic checks

                # Calculate Merkle Root
                try:
                    current_merkle_root_le = calculate_simplified_merkle_root_le(
                        coinb1_local_bin, extranonce1_local_bin, extranonce2_bin_local,
                        coinb2_local_bin, merkle_branch_local_bin_be)
                    if not current_merkle_root_le or len(current_merkle_root_le) != 32:
                        log_msg(logging.ERROR, f"[MINER {process_id}] Failed merkle root for job {current_job_id_local}. Abandoning.")
                        job_abandoned_by_process = True
                        continue # To break outer loop
                except Exception as e:
                    log_msg(logging.ERROR, f"[MINER {process_id}] Exception calculating merkle root: {e}. Abandoning.")
                    job_abandoned_by_process = True
                    continue # To break outer loop

                # Construct Block Header Template
                try:
                    header_template_le = struct.pack('<I', version_local_le) + \
                                         prevhash_local_bin_le + \
                                         current_merkle_root_le + \
                                         struct.pack('<I', ntime_local_le) + \
                                         struct.pack('<I', nbits_local_le)
                    if len(header_template_le) != 76:
                         log_msg(logging.ERROR, f"[MINER {process_id}] Header template length incorrect ({len(header_template_le)}). Abandoning.")
                         job_abandoned_by_process = True
                         continue
                except struct.error as e:
                     log_msg(logging.ERROR, f"[MINER {process_id}] Failed to pack header template: {e}. Abandoning.")
                     job_abandoned_by_process = True
                     continue
                except Exception as e:
                     log_msg(logging.ERROR, f"[MINER {process_id}] Unexpected error building header template: {e}. Abandoning.")
                     job_abandoned_by_process = True
                     continue

                # Nonce Loop
                nonce_limit = 0xFFFFFFFF
                nonce_start = process_id # Distribute nonce space
                nonce_step = num_processes

                hash_counter_batch = 0 # Count hashes in batches

                for nonce_le_int in range(nonce_start, nonce_limit + 1, nonce_step):
                    # Check events/new job/target updates roughly every 65k nonces slice
                    if (nonce_le_int & 0xFFFF) == (process_id & 0xFFFF):
                         if shutdown_event.is_set() or connection_lost_event.is_set():
                            job_abandoned_by_process = True
                            break
                         try: # Check job queue non-blockingly for new job
                            job_q.get_nowait()
                            log_msg(logging.INFO, f"[MINER {process_id}] New job available. Abandoning old job {current_job_id_local}.")
                            job_abandoned_by_process = True
                            break
                         except Empty:
                             pass

                         with shared_target_lock:
                             target_val = shared_target_mgr.value
                             if target_val is None or target_val <= 0: job_abandoned_by_process = True; share_target_loaded = False
                             elif share_target_loaded and target_val != local_share_target: local_share_target = target_val
                         if job_abandoned_by_process: break

                         # Report hash count periodically
                         if hash_counter_batch > 0:
                              try: hash_queue.put_nowait((process_id, hash_counter_batch))
                              except Full: pass # Drop batch if queue full, main loop will miss some counts for this interval
                              hash_counter_batch = 0


                    # Prepare 80-byte header
                    try:
                        nonce_le_bytes = struct.pack('<I', nonce_le_int)
                        header_le_80bytes = header_template_le + nonce_le_bytes
                        if len(header_le_80bytes) != 80:
                             log_msg(logging.ERROR, f"[MINER {process_id}] Constructed header length != 80 ({len(header_le_80bytes)}). Skipping nonce {nonce_le_int}.")
                             continue
                    except struct.error:
                        log_msg(logging.WARNING, f"[MINER {process_id}] Failed to pack nonce {nonce_le_int}. Skipping.")
                        continue

                    # Scrypt Hashing
                    try:
                        # scrypt.hash is the CPU intensive part that should release the GIL
                        hash_result_bytes = scrypt.hash(header_le_80bytes, salt=header_le_80bytes, N=1024, r=1, p=1, buflen=32)
                    except Exception as e:
                        log_msg(logging.ERROR, f"[MINER {process_id}] scrypt.hash failed for nonce {nonce_le_int}: {e}. Abandoning job.")
                        job_abandoned_by_process = True
                        break # Exit nonce loop

                    hash_counter_batch += 1
                    final_hash_le = hash_result_bytes

                    # Check result against share target
                    if share_target_loaded and is_hash_less_or_equal_target(final_hash_le, local_share_target):
                        # Share Found
                        winning_nonce_le = nonce_le_int
                        hash_hex_be = binascii.hexlify(final_hash_le[::-1]).decode()
                        share_timestamp = timestamp_us()
                        network_difficulty = calculate_difficulty_nbits(nbits_local_le)
                        share_difficulty = calculate_difficulty_from_target(int.from_bytes(final_hash_le, 'little'))
                        meets_network_target = (network_difficulty > 0 and share_difficulty >= network_difficulty)

                        print(f"\r{' '*80}\r", end='', file=sys.stderr)
                        print(f"{C_GREEN}[P{process_id} {share_timestamp}] Share found! Job: {current_job_id_local} Nonce: 0x{winning_nonce_le:08x} {'[BLOCK!]' if meets_network_target else ''}{C_RESET}", flush=True)

                        target_hex_log = f"{local_share_target:064x}" if local_share_target is not None else "NotSet"
                        log_msg(logging.INFO, f"[SHARE FOUND][P{process_id}] Job={current_job_id_local} N(LE)=0x{winning_nonce_le:08x} H(BE)={hash_hex_be} Tgt={target_hex_log} E2(LE)={bin_to_hex(extranonce2_bin_local)} {'[BLOCK!]' if meets_network_target else ''}")

                        # Submit Share (Send to main process via Queue)
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
                            # Use blocking put (default) - apply timeout to avoid hanging indefinitely
                            submit_queue.put(submit_payload, block=True, timeout=5) # Block up to 5 seconds
                            log_msg(logging.INFO, f"[SUBMIT][P{process_id}] Sent share payload for job {current_job_id_local} to submit queue.")
                        except Full:
                             log_msg(logging.WARNING, f"[SUBMIT][P{process_id}] Submit queue full, failed to submit share for job {current_job_id_local}. Dropping.")
                        except Exception as e:
                            log_msg(logging.ERROR, f"[SUBMIT][P{process_id}] Failed to put share payload onto submit queue: {e}")
                            # Cannot submit, abandon job to get a new one?
                            job_abandoned_by_process = True

                        job_abandoned_by_process = True
                        break # Exit nonce loop

                # End of Nonce Loop

                # Report any remaining hashes from the loop
                if hash_counter_batch > 0:
                    try: hash_queue.put_nowait((process_id, hash_counter_batch))
                    except Full: pass # Drop if queue full
                    hash_counter_batch = 0

                if job_abandoned_by_process: break

                # Increment Extranonce2
                if not increment_extranonce2(extranonce2_bin_local):
                    log_msg(logging.WARNING, f"[WARN][P{process_id}] E2 space wrapped for job {current_job_id_local}. E2(LE): {bin_to_hex(extranonce2_bin_local)}. Waiting for new job.")
                    job_abandoned_by_process = True
                    break
                else:
                    # Simple check if E2 returned to its starting value for this process
                    # Note: This isn't perfectly robust across processes for global E2 exhaustion,
                    # but matches the C++ 'wrap' check logic per thread slice more closely.
                    if extranonce2_size_local > 0 and bytes(extranonce2_bin_local) == initial_e2_value:
                       log_msg(logging.WARNING, f"[WARN][P{process_id}] E2 space slice potentially exhausted for job {current_job_id_local}. Waiting for new job.")
                       job_abandoned_by_process = True
                       break

            # End of Extranonce2 Loop

        # End of Main Mining Loop

    except Exception as e:
        log_msg(logging.ERROR, f"[FATAL][MINER {process_id}] Terminating due to unhandled exception: {e}")
        import traceback
        log_msg(logging.ERROR, traceback.format_exc())
        # No need to set events here, main loop handles process termination/restart

    log_msg(logging.INFO, f"[MINER {process_id}] Process finished.")

# --- Subscribe Thread Function ---
def subscribe_func(job_q, submit_q, shutdown_event, connection_lost_event, shared_target_mgr, shared_target_lock, height_lock):
    """Handles Stratum protocol communication. Runs as a thread in the main process."""
    global g_socket # Access global socket state
    global g_current_height # Access global height state via lock

    thread_name = "Subscribe"
    threading.current_thread().name = thread_name
    log_msg(logging.INFO, "[SUB] Subscribe thread started.")

    buffer_agg = ""
    last_e1_bin = b'' # Store E1 received from subscribe
    last_e2_size = 4  # Store E2 size received from subscribe
    last_ph_hex = "" # Store last prevhash hex for new block detection within this thread

    time.sleep(0.2)

    while not shutdown_event.is_set():
        sock_to_use = None
        with g_socket_lock:
            sock_to_use = g_socket

        if sock_to_use is None:
           if connection_lost_event.is_set():
                log_msg(logging.DEBUG, "[SUB] Connection lost event detected, waiting for reconnect.")
                time.sleep(1)
           else:
                # This state indicates a logic error if socket is None but connection_lost is not set
                log_msg(logging.ERROR, "[SUB] Socket is None unexpectedly but connection_lost_event is not set. Waiting.")
                time.sleep(1)
           continue

        log_msg(logging.INFO, f"[SUB] Using socket FD {sock_to_use.fileno()} for pool communication.")
        time.sleep(0.5) # Short delay before sending

        try:
            # Need to reset last_e1_bin and last_e2_size on a new connection attempt
            last_e1_bin = b''
            last_e2_size = 4
            last_ph_hex = "" # Reset last prevhash on new connection

            subscribe_future_id = 1
            subscribed = send_json_message(sock_to_use, {"id": subscribe_future_id, "method": "mining.subscribe", "params": ["SimplePythonDogeMiner/1.0"]})
            if not subscribed:
                log_msg(logging.ERROR, "[SUB] Send subscribe failed.")
                # send_json_message sets connection_lost_event_mp
                time.sleep(RECONNECT_DELAY_SECONDS)
                continue # Go back to the top of the while loop

            authorize_future_id = 2
            authed = send_json_message(sock_to_use, {"id": authorize_future_id, "method": "mining.authorize", "params": [g_wallet_addr, g_pool_password]})
            if not authed:
                log_msg(logging.ERROR, "[SUB] Send authorize failed.")
                # send_json_message sets connection_lost_event_mp
                time.sleep(RECONNECT_DELAY_SECONDS)
                continue # Go back to the top of the while loop

        except Exception as e:
             log_msg(logging.ERROR, f"[ERR][SUB] Error during initial pool communication: {e}")
             connection_lost_event.set() # Ensure event is set
             time.sleep(RECONNECT_DELAY_SECONDS)
             continue # Go back to the top of the while loop

        buffer_agg = "" # Clear buffer for new connection
        log_msg(logging.INFO, f"[SUB] Waiting for pool messages on FD {sock_to_use.fileno()}...")

        # Inner loop: Process messages while connected
        try:
            import select
            while not shutdown_event.is_set() and not connection_lost_event.is_set():
                 # Check if the global socket has changed or been closed by the main thread
                 with g_socket_lock:
                     if g_socket != sock_to_use:
                         log_msg(logging.INFO, f"[SUB] Socket FD {sock_to_use.fileno()} changed. Exiting receive loop.")
                         break # Exit inner loop

                 # Use select with a small timeout to allow checking events periodically
                 ready_to_read, _, _ = select.select([sock_to_use], [], [], 0.1)

                 if not ready_to_read:
                      # Timeout occurred, check loop conditions again
                      continue

                 # Data available, try to read
                 try:
                    chunk = sock_to_use.recv(8192)
                    if not chunk:
                        # Connection closed gracefully by pool
                        log_msg(logging.INFO, f"[SUB] Pool disconnected FD {sock_to_use.fileno()} (read 0 bytes).")
                        raise socket.error("Pool closed connection") # Trigger reconnect
                 except socket.timeout:
                      # This shouldn't happen with select timeout but handle defensively
                      continue
                 except socket.error as e:
                     # Handle socket errors during recv
                     log_msg(logging.ERROR, f"[ERR][SUB] Socket error during recv on FD {sock_to_use.fileno()}: {e}")
                     raise socket.error(f"Socket recv error: {e}") # Re-raise to be caught by outer try/except

                 # Process received data
                 buffer_agg += chunk.decode('utf-8', errors='replace')

                 # Process line by line from aggregated buffer
                 while '\n' in buffer_agg:
                     line, buffer_agg = buffer_agg.split('\n', 1)
                     line = line.strip()
                     if not line: continue # Skip empty lines

                     # Parse JSON
                     try:
                         message = json.loads(line)
                         # log_msg(logging.DEBUG, f"[DEBUG][SUB] Recv: {line}") # Too noisy
                     except json.JSONDecodeError:
                         log_msg(logging.ERROR, f"[ERROR][SUB] JSON parse error for line: {line[:200]}...")
                         continue # Skip this line, try next

                     # Process the parsed message
                     # Pass E1/E2 state by reference (list is mutable) or return updated state
                     # Returning updated state is cleaner in Python
                     last_e1_bin, last_e2_size, last_ph_hex = process_pool_message(
                         message, line, job_q, submit_q, shared_target_mgr,
                         shared_target_lock, height_lock,
                         last_e1_bin, last_e2_size, last_ph_hex # Pass current state
                     )

        except socket.error as e:
            # Handle socket errors (connection reset, broken pipe, etc.) caught by the inner loop
            log_msg(logging.ERROR, f"[ERR][SUB] Socket error on FD {sock_to_use.fileno()}: {e}. Signaling connection lost.")
            connection_lost_event.set() # Signal connection lost using MP event
        except RuntimeError as e: # Catch critical errors like auth/sub failure explicitly raised
             log_msg(logging.FATAL, f"[FATAL][SUB] Critical error processing message: {e}. Signaling connection lost.")
             connection_lost_event.set() # Signal connection lost
        except Exception as e:
            log_msg(logging.ERROR, f"[FATAL][SUB] Unexpected error in receive loop: {e}")
            import traceback
            log_msg(logging.ERROR, traceback.format_exc())
            connection_lost_event.set()

        # --- After exiting inner loop ---
        if shutdown_event.is_set():
            log_msg(logging.INFO, "[SUB] Shutdown signal received, exiting.")
            break # Exit outer loop

        # If we exited the inner loop not because of shutdown or socket error, assume connection lost
        if not connection_lost_event.is_set():
            log_msg(logging.WARNING, "[SUB] Exited receive loop unexpectedly. Signaling connection lost.")
            connection_lost_event.set()

        log_msg(logging.INFO, "[SUB] Waiting briefly before checking connection state again.")
        time.sleep(0.5)

    # --- End main subscribe loop ---
    log_msg(logging.INFO, "[SUB] Subscribe thread finished.")
    # Subscribe thread exits, will be joined by main thread.

# --- Process Pool Messages ---
def process_pool_message(message, original_line, job_q, submit_q, shared_target_mgr, shared_target_lock, height_lock, last_e1_bin, last_e2_size, last_ph_hex):
    """Parses pool messages and updates state/queues. Returns updated state (E1, E2 size, last_ph_hex)."""
    msg_id = message.get('id')
    method = message.get('method')
    params = message.get('params')
    result = message.get('result')
    error = message.get('error')

    try:
        if msg_id is not None: # Response
            if error:
                err_str = json.dumps(error)
                log_msg(logging.ERROR, f"[ERR][SUB] Pool error response ID {msg_id}: {err_str}")
                print(f"\r{' '*80}\r{C_RED}[{timestamp_us()}] Pool Error (ID {msg_id}): {err_str}{C_RESET}", file=sys.stderr, flush=True)
                if msg_id in (1, 2): # Subscribe or Authorize failure
                     # Signal critical error that main loop should handle (reconnect or shutdown)
                     raise RuntimeError("Pool indicated critical failure")
            elif result is not None or method is None: # Success Response
                if msg_id == 1: # Subscribe
                    if isinstance(result, list) and len(result) >= 2:
                        try:
                           # Find extranonce1 (hex string) and extranonce2_size (integer) in the result list
                           e1h_idx, e2s_idx = -1, -1
                           for i, item in enumerate(result):
                               if isinstance(item, str) and len(item) % 2 == 0:
                                   try: binascii.unhexlify(item); e1h_idx = i; break # Found valid hex
                                   except: pass # Not valid hex
                           for i, item in enumerate(result):
                               if isinstance(item, int): e2s_idx = i; break # Found integer

                           if e1h_idx != -1 and e2s_idx != -1:
                                e1h = result[e1h_idx]
                                e2s_i = result[e2s_idx]
                                e1b = hex_to_bin(e1h)
                                if e1b is not None:
                                    last_e1_bin = e1b # Update subscribe thread state
                                    last_e2_size = int(e2s_i) # Update subscribe thread state
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
                elif msg_id == 2: # Authorize
                    auth_ok = bool(result)
                    log_msg(logging.INFO, f"[SUB] Authorization {'successful' if auth_ok else 'failed'}.")
                    if auth_ok: print(f"{C_GREEN}[POOL] Authorization OK.{C_RESET}", flush=True)
                    else:
                         err_str = json.dumps(result)
                         print(f"\r{' '*80}\r{C_RED}[{timestamp_us()}] AUTHORIZATION FAILED! Result: {err_str}. Check wallet/password.{C_RESET}", file=sys.stderr, flush=True)
                         raise RuntimeError("Authorization failed")
                elif isinstance(msg_id, int): # Share Submit Ack
                    share_accepted = bool(result)
                    if share_accepted:
                        log_msg(logging.INFO, f"[SUB] Share (ID {msg_id}) accepted.")
                        print(f"{C_GREEN}[{timestamp_us()}] Share Accepted! (ID {msg_id}){C_RESET}", flush=True)
                    else:
                        res_str = json.dumps(result)
                        log_msg(logging.WARNING, f"[WARN][SUB] Share (ID {msg_id}) rejected. Result: {res_str}")
                        print(f"\r{' '*80}\r{C_YELLOW}[{timestamp_us()}] Share Rejected? (ID {msg_id}) Result: {res_str}{C_RESET}", file=sys.stderr, flush=True)

        elif method: # Notification
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
                        if not all(b is not None and len(b) == 32 for b in tmbl_be): raise ValueError(f"Bad merkle branch hex list")

                        t_v = int.from_bytes(hex_to_bin(v_h), 'big')
                        t_nb = int.from_bytes(hex_to_bin(nb_h), 'big')
                        t_nt = int.from_bytes(hex_to_bin(nt_h), 'big')

                        # Ensure E1/E2 size are known before creating job payload
                        if not last_e1_bin or last_e2_size <= 0:
                            log_msg(logging.WARNING, f"[WARN][SUB] Received mining.notify but E1/E2 size not set yet. Skipping job {job_id_str}.")
                            # Return current state (unchanged)
                            return last_e1_bin, last_e2_size, last_ph_hex

                        # Package job data for miner processes
                        job_payload_dict = {
                            'job_id': job_id_str,
                            'prevhash_bin_le': tph_be[::-1], # Store LE binary
                            'coinb1_bin': tcb1,
                            'coinb2_bin': tcb2,
                            'merkle_branch_bin_be': tmbl_be, # Store list of BE binary
                            'version_le': t_v, # Store LE integer
                            'nbits_le': t_nb, # Store LE integer
                            'ntime_le': t_nt, # Store LE integer
                            'clean_jobs': bool(clean_j),
                            'extranonce1_bin': last_e1_bin, # Include E1 from subscribe state
                            'extranonce2_size': last_e2_size # Include E2 size from subscribe state
                        }

                        # Log Job Info & Push to Queue
                        current_ph_hex = ph_h
                        # Use the last_ph_hex state variable from subscribe_func scope
                        new_block = (current_ph_hex != last_ph_hex)
                        last_ph_hex = current_ph_hex # Update state variable

                        if new_block:
                            # Access g_current_height safely with the lock
                            with height_lock:
                                # Attempt to increment height if we have an initial value > 0
                                if g_current_height > 0:
                                    g_current_height += 1
                                ch = g_current_height # Local copy for logging
                            net_diff = calculate_difficulty_nbits(t_nb)
                            log_msg(logging.INFO, f"[JOB] New Block ~{ch if ch > 0 else 0}. Job: {job_id_str} (Clean:{'Y' if bool(clean_j) else 'N'} NetDiff(Ref):{net_diff:.3e})")
                            print(f"\r{' '*80}\r{C_YELLOW}[*] New Block ~{ch if ch>0 else 0} | NetDiff(Ref): {net_diff:.3e} | Job: {job_id_str}{C_RESET}", flush=True)
                        else:
                            log_msg(logging.INFO, f"[JOB] New Job: {job_id_str} (Clean:{'Y' if bool(clean_j) else 'N'})")

                        try:
                            # Put job payload onto the queue for miners (blocks if full)
                            job_q.put(job_payload_dict, block=True, timeout=5)
                        except Full:
                            log_msg(logging.WARNING, f"[WARN][SUB] Job queue full, miners too slow? Skipping job {job_id_str}.")
                        except Exception as e:
                             log_msg(logging.ERROR, f"[ERR][SUB] Error putting job {job_id_str} onto queue: {e}")


                    except (ValueError, TypeError, IndexError, struct.error) as e:
                         log_msg(logging.ERROR, f"[ERR][SUB] mining.notify has bad params: {e}. Line: {original_line[:200]}...")
                    except Exception as e:
                         log_msg(logging.ERROR, f"[ERR][SUB] Unexpected error processing mining.notify: {e}. Line: {original_line[:200]}...")
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
                            new_target_f = float(TARGET1_SCRYPT_SCALE) / float(pool_difficulty)
                            new_target_int = int(new_target_f) # This should be a large integer

                            # Clamp target to 256-bit range (1 to MAX_TARGET_256)
                            new_target_int = max(1, min(new_target_int, MAX_TARGET_256))
                            # Ensure it's stored as a Python integer object via Manager
                            with shared_target_lock:
                                # Assign the large integer to the Manager.Value
                                shared_target_mgr.value = new_target_int

                            actual_share_diff_btc_ref = calculate_difficulty_from_target(shared_target_mgr.value)
                            target_hex_log = f"{shared_target_mgr.value:064x}" if shared_target_mgr.value is not None else "NotSet"
                            log_msg(logging.INFO, f"[SUB] Updated Scrypt Share Target {target_hex_log}. PoolDiff: {pool_difficulty:.5f} -> ShareDiff(Ref): {actual_share_diff_btc_ref:.5f}")

                        except Exception as e:
                             log_msg(logging.ERROR, f"[ERR][SUB] Error calculating Scrypt share target: {e}")
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
        # Re-raise critical errors to be caught by subscribe_func
        raise
    except Exception as e:
        log_msg(logging.ERROR, f"[ERROR][SUB] Exception processing message: {e}. Line: {original_line[:200]}...")
        import traceback
        log_msg(logging.ERROR, traceback.format_exc())

    # Return the updated state from this function call
    return last_e1_bin, last_e2_size, last_ph_hex


# --- Periodic Status Logger ---
def log_periodic_status():
    """Aggregates hash counts and logs status."""
    global g_total_hashes_reported, g_aggregated_hash_rate, g_last_aggregated_report_time
    global g_process_hash_counts
    global shared_target # Access global Manager.Value placeholder

    now = time.monotonic()
    duration = now - g_last_aggregated_report_time

    if duration < 0.1: return

    # Collect and aggregate hash counts from processes
    try:
        while True:
            proc_id, count = hash_queue.get_nowait()
            g_process_hash_counts[proc_id] = g_process_hash_counts.get(proc_id, 0) + count
    except Empty:
        pass

    current_total_hashes = sum(g_process_hash_counts.values())

    delta_hashes = current_total_hashes - g_total_hashes_reported
    # Reset total if count goes down unexpectedly or time jump is large
    if delta_hashes < 0 or duration > (STATUS_LOG_INTERVAL_SECONDS * 2):
         log_msg(logging.WARNING, "[STATUS] Hash count reset detected or large time jump. Resetting total.")
         g_total_hashes_reported = current_total_hashes
         delta_hashes = 0

    current_rate = (delta_hashes / duration) if duration > 0 else 0.0

    g_aggregated_hash_rate = current_rate
    g_total_hashes_reported = current_total_hashes
    g_last_aggregated_report_time = now

    with g_current_height_lock: height_local = g_current_height
    # Access shared_target Manager.Value via the global placeholder
    share_target_val_for_status = None
    with shared_target_lock:
        if shared_target is not None: # Check if Manager.Value is initialized
            share_target_val_for_status = shared_target.value


    difficulty_share_local_btc_ref = calculate_difficulty_from_target(share_target_val_for_status) if share_target_val_for_status is not None and share_target_val_for_status > 0 else 0.0
    # Note: Network Difficulty needs the last job's nbits, which isn't currently stored globally in main process.
    # We'll omit NetDiff from the status print for now, it's logged when a new block/job arrives.

    display_rate = current_rate
    rate_unit = "H/s"
    if display_rate >= 1e12: display_rate /= 1e12; rate_unit = "TH/s"
    elif display_rate >= 1e9: display_rate /= 1e9; rate_unit = "GH/s"
    elif display_rate >= 1e6: display_rate /= 1e6; rate_unit = "MH/s"
    elif display_rate >= 1e3: display_rate /= 1e3; rate_unit = "kH/s"

    log_msg(logging.INFO, f"[STATUS] Height: ~{height_local if height_local>0 else 0} | ShareDiff(Ref): {difficulty_share_local_btc_ref:.3f} | Rate: {display_rate:.2f} {rate_unit}")

    status_line = f"[{timestamp_us()}] [STATUS] H: ~{height_local if height_local>0 else 0} | ShareD(Ref): {difficulty_share_local_btc_ref:.3f} | Rate: {display_rate:.2f} {rate_unit}"
    print(f"\r{' '*80}\r{C_CYAN}{status_line}{C_RESET}", end='', file=sys.stderr)
    sys.stderr.flush()

# --- Share Submission Handler ---
def handle_share_submission(sock):
    """Checks submit queue and sends shares if socket is available."""
    if not sock: return False

    try:
        submit_payload = submit_queue.get_nowait()
        # payload: [wallet_addr, job_id, extranonce2_hex, ntime_hex_be, nonce_hex_be]

        # Use a unique ID for each submission
        submit_id = int(time.time() * 1000) + random.randint(0, 999)
        payload_dict = {
            "id": submit_id,
            "method": "mining.submit",
            "params": submit_payload
        }

        log_msg(logging.INFO, f"[MAIN] Sending share submission ID {submit_id} for job {submit_payload[1]}...")

        success = False
        with g_socket_lock:
             # Only send if the socket hasn't changed
             if g_socket == sock:
                 success = send_json_message(sock, payload_dict)
             else:
                 log_msg(logging.WARNING, f"[MAIN] Socket changed while submitting ID {submit_id}. Dropping share.")
                 # Share payload is lost if socket changes, will need to be re-mined on the new job
                 return False # Indicate send failed

        if success:
            # Share accepted/rejected response will come back via subscribe thread and be processed
            pass # response handled in process_pool_message
        else:
            # send_json_message sets connection_lost_event_mp on failure
            log_msg(logging.ERROR, f"[MAIN] Failed to send share submission ID {submit_id}.")
            return False # Indicate send failed

        return True # Indicate a share was processed

    except Empty:
        return False # Indicate no share was processed
    except Exception as e:
        log_msg(logging.ERROR, f"[ERROR][MAIN] Exception handling share submission: {e}")
        return False

# --- Main Function ---
def main():
    """Main entry point for the miner."""
    global g_socket
    global g_processes
    global g_process_hash_counts
    global g_total_hashes_reported, g_aggregated_hash_rate, g_last_aggregated_report_time
    global g_current_height
    global shared_target, shared_target_lock # Access the global shared target placeholder

    signal.signal(signal.SIGINT, handle_sigint)
    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    print(f"Loading Dogecoin configuration from {CONFIG_FILE}...")
    if not load_config():
        sys.exit(1)

    setup_file_logger()

    log_msg(logging.INFO,"--------------------------------------------------")
    log_msg(logging.INFO,"Dogecoin (Scrypt) Miner starting:")
    log_msg(logging.INFO,f"  Pool: {g_pool_host}:{g_pool_port}")
    log_msg(logging.INFO,f"  Wallet/Worker: {g_wallet_addr}")
    log_msg(logging.INFO,f"  Password: {'[empty]' if not g_pool_password else '(set)'}")
    log_msg(logging.INFO,f"  Processes: {g_processes}")
    log_msg(logging.INFO,f"  Log File: {g_log_file}")
    log_msg(logging.INFO,"--------------------------------------------------")

    print(f"{C_MAG}--- Simple Python Dogecoin (Scrypt) Miner ---{C_RESET}")
    print(f"{C_MAG}----------------------------------------{C_RESET}")
    print(f"{C_MAG} Wallet: {C_YELLOW}{g_wallet_addr}{C_RESET}")
    print(f"{C_MAG} Processes: {C_YELLOW}{g_processes}{C_RESET}")
    print(f"{C_MAG} Pool: {C_YELLOW}{g_pool_host}:{g_pool_port}{C_RESET}")
    print(f"{C_MAG}----------------------------------------{C_RESET}")
    sys.stdout.flush()

    log_msg(logging.INFO,"[MAIN] Fetching initial Dogecoin block height...")
    print("[INFO] Fetching initial Dogecoin block height from API...")
    sys.stdout.flush()
    initial_height = get_current_block_height()
    with g_current_height_lock:
        g_current_height = initial_height
    if initial_height > 0:
        print(f"{C_CYAN}[INFO] Initial Dogecoin block height estimated at: {initial_height}{C_RESET}")
        log_msg(logging.INFO, f"[MAIN] Initial Dogecoin block height from API: {initial_height}")
    else:
        print(f"{C_YELLOW}[WARN] Could not fetch initial Dogecoin block height.{C_RESET}")
        log_msg(logging.WARNING, "[WARN] Failed to fetch initial Dogecoin block height.")
    sys.stdout.flush()

    height_check_interval = 15 * 60 # 15 minutes
    last_height_check_time = time.monotonic()
    status_log_interval = STATUS_LOG_INTERVAL_SECONDS
    last_status_log_time = time.monotonic()

    # --- Create Multiprocessing Manager and Shared Objects ---
    # Manager must be created in the main process before child processes start
    manager = multiprocessing.Manager()
    # Create the shared target value using the manager
    # 'object' type code allows storing arbitrary picklable Python objects (like large integers)
    shared_target_mgr = manager.Value('object', TARGET1_SCRYPT_SCALE) # Initialize with Scrypt Diff 1 target scale
    # Update the global placeholder in the main process
    shared_target = shared_target_mgr
    log_msg(logging.INFO, "[MAIN] Created multiprocessing Manager and shared_target.")


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
            print(f"{C_YELLOW}[NET] Connection failed. Retrying in {RECONNECT_SECONDS} seconds...{C_RESET}", file=sys.stderr)
            sys.stderr.flush()
            g_shutdown_event_mp.wait(timeout=RECONNECT_DELAY_SECONDS)
            if g_shutdown_event_mp.is_set(): break
            continue

        # Connection Successful
        with g_socket_lock:
             g_socket = new_socket
        log_msg(logging.INFO, f"[MAIN] Connection successful (FD: {g_socket.fileno()}). Starting processes...")
        print(f"{C_GREEN}[NET] Connected! Starting {g_processes} miner processes.{C_RESET}")
        sys.stdout.flush()

        # Clear queues and reset state for new connection
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

        # Reset Shared Target value via Manager object
        with shared_target_lock:
            shared_target_mgr.value = TARGET1_SCRYPT_SCALE # Reset to Diff 1 scale
            log_msg(logging.INFO, "[MAIN] Reset shared_target_mgr value to Scrypt Difficulty 1 scale.")

        # Reset Hashrate Counters (in main process)
        g_process_hash_counts = {}
        g_total_hashes_reported = 0
        g_aggregated_hash_rate = 0.0
        g_last_aggregated_report_time = time.monotonic()

        # Start Subscribe Thread
        # Pass the Manager-created shared object and its lock
        sub_thread = threading.Thread(
            target=subscribe_func,
            args=(job_queue, submit_queue, g_shutdown_event_mp, g_connection_lost_event_mp, shared_target_mgr, shared_target_lock, g_current_height_lock),
            name="Subscribe", daemon=True)
        sub_thread.start()

        # Start Miner Processes
        miner_processes = []
        for i in range(g_processes):
            # Pass the Manager-created shared object and its lock to the processes
            miner_proc = multiprocessing.Process(
                target=miner_process_func,
                args=(i, g_processes, job_queue, submit_queue, hash_queue, g_shutdown_event_mp, g_connection_lost_event_mp, shared_target_mgr, shared_target_lock),
                name=f"MinerProc-{i}")
            miner_processes.append(miner_proc)
            g_process_hash_counts[i] = 0
            miner_proc.start()

        # Main Process Monitoring Loop
        log_msg(logging.INFO, "[MAIN] Entering monitoring loop.")
        current_socket_for_submit = g_socket

        while not g_shutdown_event_mp.is_set() and not g_connection_lost_event_mp.is_set():

            # Handle Share Submissions (Non-blocking check)
            shares_processed_this_tick = 0
            # Process multiple shares if available to avoid queue buildup
            while handle_share_submission(current_socket_for_submit):
                 shares_processed_this_tick += 1
                 # Limit submissions per tick to avoid blocking status updates etc.
                 if shares_processed_this_tick > 10:
                     break

            # Periodic Status Log
            now_monotonic = time.monotonic()
            if now_monotonic - last_status_log_time >= status_log_interval:
                try: log_periodic_status()
                except Exception as e: log_msg(logging.ERROR, f"[ERROR][STATUS] Error during status log: {e}")
                last_status_log_time = now_monotonic

            # Periodic Height Check
            if now_monotonic - last_height_check_time >= height_check_interval:
                log_msg(logging.INFO, "[MAIN] Performing periodic external height check...")
                external_height = get_current_block_height()
                if external_height > 0:
                    with g_current_height_lock:
                        local_height = g_current_height
                        if external_height > local_height:
                            log_msg(logging.INFO, f"[MAIN] External height {external_height} > local height {local_height}. Updating.")
                            print(f"\n{C_CYAN}[INFO] External height update detected: {external_height}{C_RESET}", flush=True)
                            g_current_height = external_height
                        elif external_height < local_height and local_height > 0:
                            log_msg(logging.WARNING, f"[WARN][MAIN] External height {external_height} < local height {local_height}. Minor discrepancy.")
                else:
                    log_msg(logging.WARNING, "[WARN][MAIN] Periodic external height check failed.")
                last_height_check_time = now_monotonic

            # Sleep to yield CPU if no shares were processed immediately
            if shares_processed_this_tick == 0:
                 time.sleep(0.01)

        # Disconnection or Shutdown Detected
        if g_shutdown_event_mp.is_set():
             log_msg(logging.INFO, "[MAIN] Shutdown requested. Stopping processes...")
        elif g_connection_lost_event_mp.is_set():
             log_msg(logging.INFO, "[MAIN] Connection lost. Stopping processes and preparing to reconnect...")
             ts = timestamp_us()
             print(f"\r{' '*80}\r{C_YELLOW}[{ts}] Pool connection lost. Reconnecting...{C_RESET}", file=sys.stderr, flush=True)

        # --- Coordinated Process/Thread Shutdown ---
        # 1. Signal processes to stop
        # Events should already be set by handling logic, but ensure they are.
        g_connection_lost_event_mp.set() # Signal miners waiting on queue timeouts
        g_shutdown_event_mp.set()       # Signal processes in their main loop condition

        # 2. Close the socket (interrupts subscribe thread)
        closed_socket_fd = -1
        with g_socket_lock:
             if g_socket:
                 closed_socket_fd = g_socket.fileno()
                 try: g_socket.shutdown(socket.SHUT_RDWR)
                 except socket.error: pass # Ignore errors if already closed/unconnected
                 try: g_socket.close()
                 except socket.error as e: log_msg(logging.WARNING, f"[MAIN] Error closing socket FD {closed_socket_fd}: {e}")
                 g_socket = None
        current_socket_for_submit = None

        # 3. Join processes (with timeout)
        log_msg(logging.INFO, f"[MAIN] Joining {len(miner_processes)} miner processes...")
        join_timeout_per_proc = 5.0
        start_join = time.monotonic()
        joined_count = 0
        for proc in miner_processes:
             # Calculate remaining time to distribute across remaining processes
             remaining_timeout = max(0.1, (start_join + join_timeout_per_proc * g_processes) - time.monotonic())
             remaining_procs_to_join = len(miner_processes) - joined_count
             proc_join_timeout = remaining_timeout / remaining_procs_to_join if remaining_procs_to_join > 0 else 0.1

             proc.join(timeout=proc_join_timeout)

             if proc.is_alive():
                 log_msg(logging.WARNING, f"[MAIN] Process {proc.name} did not join within timeout. Terminating.")
                 try:
                      proc.terminate() # Force termination
                      proc.join(timeout=2.0) # Wait a bit more after terminate
                      if proc.is_alive(): log_msg(logging.ERROR, f"[MAIN] Process {proc.name} did not terminate after terminate().")
                      else: log_msg(logging.INFO, f"[MAIN] Process {proc.name} terminated.")
                 except Exception as e: log_msg(logging.ERROR, f"[MAIN] Error terminating process {proc.name}: {e}")
             else:
                 log_msg(logging.INFO, f"[MAIN] Process {proc.name} joined.")
                 joined_count += 1
        miner_processes.clear()
        log_msg(logging.INFO, f"[MAIN] Joined {joined_count}/{g_processes} miner processes.")

        # 4. Join Subscribe Thread (should exit after socket is closed and events are set)
        if sub_thread and sub_thread.is_alive():
             log_msg(logging.INFO, "[MAIN] Joining subscribe thread...")
             sub_thread.join(timeout=5.0)
             if sub_thread.is_alive():
                  log_msg(logging.WARNING, "[MAIN] Subscribe thread did not join within timeout.")
             else:
                  log_msg(logging.INFO, "[MAIN] Subscribe thread joined.")


        # --- Prepare for Reconnect Delay ---
        # If we are shutting down, break the main loop immediately
        if g_shutdown_event_mp.is_set():
             log_msg(logging.INFO, "[MAIN] Shutdown confirmed. Exiting main loop.")
             break
        else:
             # If it was just a connection loss, wait before trying to reconnect
             log_msg(logging.INFO, f"[MAIN] Waiting {RECONNECT_DELAY_SECONDS}s before reconnect...")
             # Wait, but allow interruption by SIGINT (which sets shutdown event)
             g_shutdown_event_mp.wait(timeout=RECONNECT_DELAY_SECONDS)
             if g_shutdown_event_mp.is_set(): break # Exit if shutdown during wait

    # --- End Main Reconnect Loop ---

    # --- Final Cleanup ---
    log_msg(logging.INFO, "[MAIN] Dogecoin Miner shutting down cleanly.")
    print(f"\n{C_GREEN}Dogecoin Miner exiting...{C_RESET}")
    sys.stdout.flush()

    # Attempt one last status log
    try: log_periodic_status()
    except Exception as e: log_msg(logging.ERROR, f"[ERROR][STATUS] Error during final status log: {e}")

    # Clean up Manager resources (important)
    if 'manager' in locals() and manager:
        try:
            manager.shutdown()
            log_msg(logging.INFO, "[MAIN] Multiprocessing Manager shut down.")
        except Exception as e:
            log_msg(logging.ERROR, f"[MAIN] Error shutting down Manager: {e}")


    # Close file handler explicitly
    if file_handler:
        try: file_handler.close()
        except Exception as e: print(f"{C_YELLOW}[WARN] Error closing log file handler: {e}{C_RESET}", file=sys.stderr)

    # Exit the main process
    sys.exit(0)


if __name__ == "__main__":
    # This block is protected by the __main__ guard
    multiprocessing.freeze_support() # Needed for some packaging scenarios (optional but good practice)
    main()
