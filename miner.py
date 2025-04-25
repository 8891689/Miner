#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author：8891689
# Assist in creation：gemini
import socket
import json
import time
import hashlib
import binascii
import threading
import logging
import signal
import sys
import os
import struct
from datetime import datetime
from math import log2, pow
from collections import deque
# Need select for non-blocking socket checks in subscribe thread
try:
    import select
except ImportError:
    print("Error: The 'select' module is required but not available on this platform.", file=sys.stderr)
    sys.exit(1)

# --- Configuration ---
CONFIG_FILE = "config.json"
g_config = {
    "pool_host": "stratum.example.com",
    "pool_port": 3333,
    "wallet_address": "YOUR_BTC_WALLET_ADDRESS",
    "threads": 1,
    "pool_password": "x",
    "log_file": "miner_py.log"
}

# --- Global State ---
g_sock = None
g_sock_lock = threading.Lock()
g_sigint_shutdown = threading.Event()
g_connection_lost = threading.Event()
g_new_job_available = threading.Condition() # Needs an underlying lock

# Job Data (Protected by g_new_job_available lock)
g_job_data = {
    "job_id": None,
    "prevhash": None, # bytes (little-endian)
    "coinb1": None,   # bytes
    "coinb2": None,   # bytes
    "merkle_branch": [], # list of bytes (big-endian)
    "version": None,  # int (little-endian host format)
    "nbits": None,    # int (little-endian host format, parsed from BE hex)
    "ntime": None,    # int (little-endian host format, parsed from BE hex)
    "clean_jobs": False,
    "extranonce1": None, # bytes
    "extranonce2_size": 4, # int
    "share_target": (2**256 - 1) // (2**32) # Initial Diff 1 target (approx)
}
g_current_height = -1 # Start at -1, update on first block change detect

# Hashrate Calculation
g_hash_counts = deque(maxlen=120) # Store (timestamp, hashes) for ~2 minute window
g_total_hashes_reported = 0
g_last_status_time = time.monotonic()
g_status_lock = threading.Lock()
g_shares_accepted = 0
g_shares_rejected = 0

# --- Custom Colored Formatter ---
class ColoredFormatter(logging.Formatter):
    """A logging formatter that adds ANSI color codes based on log level."""

    # ANSI escape codes
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Basic Colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m' # 綠色
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m' # 品紅色/紫紅色
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Define colors for log levels (Prefixes for the whole line)
    LOG_LEVEL_COLORS = {
        # DEBUG: 使用暗淡白色 (灰色)
        logging.DEBUG:    DIM + WHITE,
        # INFO: 使用綠色
        logging.INFO:     GREEN,
        # WARNING: 使用品紅色 (如果想更醒目但不用黃/紅)
        logging.WARNING:  MAGENTA,
        # ERROR: 使用標準紅色
        logging.ERROR:    RED,
        # CRITICAL: 使用粗體紅色
        logging.CRITICAL: BOLD + RED,
    }

    def __init__(self, fmt=None, datefmt=None, style='%', use_color=True):
        super().__init__(fmt, datefmt, style)
        self.use_color = use_color

    def format(self, record):
        log_message = super().format(record) # Get standard formatted message
        if self.use_color:
            color_prefix = self.LOG_LEVEL_COLORS.get(record.levelno, self.WHITE) # Default to white
            return f"{color_prefix}{log_message}{self.RESET}" # Add prefix and reset
        else:
            return log_message
            
# --- Logging Setup ---
# Console shows INFO+, File shows INFO+ (or DEBUG+ if file_handler level changed)
# Standard formatter for the file log
log_formatter = logging.Formatter('[%(asctime)s.%(msecs)03d] [%(levelname)s][%(threadName)s] %(message)s', datefmt='%H:%M:%S')
# Colored formatter for the console
# Check if stderr is a TTY (supports color) before enabling color
use_console_color = sys.stderr.isatty()
console_formatter = ColoredFormatter('[%(asctime)s.%(msecs)03d] [%(levelname)s][%(threadName)s] %(message)s', datefmt='%H:%M:%S', use_color=use_console_color)

logger = logging.getLogger("Miner")
logger.setLevel(logging.DEBUG) # Keep root logger level low

# File Handler (Set level here, e.g., INFO or DEBUG)
try:
    file_handler = logging.FileHandler(g_config['log_file'], mode='a', encoding='utf-8')
    file_handler.setFormatter(log_formatter) # <<< Use standard formatter
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)
except Exception as e:
    print(f"Error setting up initial file logger: {e}", file=sys.stderr)
    file_handler = None

# Console Handler (Shows essential info: INFO and higher)
console_handler = logging.StreamHandler(sys.stderr)
console_handler.setFormatter(console_formatter) # <<< Use colored formatter
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)

# --- Constants ---
DIFFICULTY_1_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
# --- How often the status thread logs the status line (in seconds) ---
STATUS_LOG_INTERVAL_SECONDS = 30 # Log status every 30 seconds
RECONNECT_DELAY_SECONDS = 5

# --- Helper Functions ---

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii') if b else ""

def hex_to_bytes(h: str) -> bytes | None:
    try:
        return binascii.unhexlify(h) if h else None
    except binascii.Error:
        # Log at ERROR level, as this indicates bad data from pool or logic error
        logger.error(f"Invalid hex string received: '{h}'")
        return None

def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def reverse_bytes(b: bytes) -> bytes:
    return b[::-1]

def load_config() -> bool:
    global g_config, logger, file_handler
    if not os.path.exists(CONFIG_FILE):
        logger.error(f"Config file '{CONFIG_FILE}' not found.")
        try:
            with open(CONFIG_FILE, 'w') as f:
                example_config = {
                    "pool_host": "stratum.example.com", "pool_port": 3333,
                    "wallet_address": "YOUR_BTC_WALLET_ADDRESS.WorkerName",
                    "threads": 1, "pool_password": "x", "log_file": "miner_py.log"
                }
                json.dump(example_config, f, indent=2)
            logger.info(f"Created example config file '{CONFIG_FILE}'. Please edit it.")
        except Exception as e: logger.error(f"Could not create example config file: {e}")
        return False

    try:
        with open(CONFIG_FILE, 'r') as f: loaded_config = json.load(f)
        required_keys = ["pool_host", "pool_port", "wallet_address", "threads"]
        for key in required_keys:
            if key not in loaded_config: raise ValueError(f"Missing required key: '{key}'")
        if not isinstance(loaded_config["pool_port"], int) or not (0 < loaded_config["pool_port"] < 65536): raise ValueError("Invalid pool_port")
        if not isinstance(loaded_config["threads"], int) or loaded_config["threads"] <= 0: raise ValueError("Invalid threads value")
        if not loaded_config["wallet_address"] or loaded_config["wallet_address"] == "YOUR_BTC_WALLET_ADDRESS.WorkerName": raise ValueError("Invalid wallet_address")

        g_config.update(loaded_config)

        if file_handler and g_config['log_file'] != file_handler.baseFilename:
             #logger.info(f"Log file changing from {file_handler.baseFilename}")
             logger.removeHandler(file_handler)
             file_handler.close()
             try:
                 file_handler = logging.FileHandler(g_config['log_file'], mode='a', encoding='utf-8')
                 file_handler.setFormatter(log_formatter)
                 file_handler.setLevel(logging.INFO) # Reset level on new handler
                 logger.addHandler(file_handler)
                 logger.info(f"Log file set to: {g_config['log_file']}")
             except Exception as e:
                logger.error(f"Error setting up new file logger '{g_config['log_file']}': {e}")
                file_handler = None
        logger.info("Configuration loaded successfully.")
        return True
    except json.JSONDecodeError as e: logger.error(f"Failed to parse JSON from '{CONFIG_FILE}': {e}"); return False
    except ValueError as e: logger.error(f"Invalid configuration in '{CONFIG_FILE}': {e}"); return False
    except Exception as e: logger.error(f"Error loading config from '{CONFIG_FILE}': {e}"); return False

def calculate_difficulty_from_nbits(nbits_le: int) -> float:
    """Calculates difficulty from nBits (which is stored in host little-endian format)."""
    # DEBUG log added to see the input value
    logger.debug(f"Calculating diff from nbits_le: {nbits_le:08x}")
    if nbits_le == 0:
        logger.debug("nbits_le is 0, returning 0.0 diff")
        return 0.0

    # Convert nbits (assumed LE host format) to BE bytes for parsing exponent/coeff
    try:
        nbits_be_bytes = nbits_le.to_bytes(4, 'little')
    except OverflowError:
         logger.error(f"nbits value {nbits_le:08x} too large to fit in 4 bytes LE.")
         return 0.0
    nbits_be = int.from_bytes(nbits_be_bytes, 'big')

    exponent = (nbits_be >> 24) & 0xFF
    coefficient = nbits_be & 0x00FFFFFF
    # DEBUG log added for intermediate values
    logger.debug(f"nBits BE: {nbits_be:08x}, Exponent: {exponent}, Coefficient: {coefficient}")

    # Reference: https://en.bitcoin.it/wiki/Difficulty#What_is_the_formula_for_difficulty
    if coefficient == 0 or not (3 <= exponent <= 32): # Bitcoin mainnet nbits constraints
        logger.warning(f"Invalid nBits exponent({exponent})/coefficient({coefficient}) derived from LE {nbits_le:08x}, returning 0.0 diff")
        return 0.0 # Invalid nBits format

    # target = coefficient * 2**(8*(exponent-3))
    try:
        target = coefficient * (2**(8 * (exponent - 3)))
    except OverflowError:
        logger.error(f"Target calculation overflowed: coeff={coefficient} exp={exponent}")
        return float('inf') # Or perhaps 0.0 depending on desired handling

    # difficulty = difficulty_1_target / target
    difficulty = float(DIFFICULTY_1_TARGET) / target if target != 0 else float('inf')
    logger.debug(f"Calculated Target: {target}, Difficulty: {difficulty}")
    return difficulty

def calculate_difficulty_from_target(target: int) -> float:
    if target <= 0: return float('inf')
    difficulty = float(DIFFICULTY_1_TARGET) / target
    return difficulty

def calculate_target_from_difficulty(difficulty: float) -> int:
    if difficulty <= 0: return 2**256 - 1
    target = int(DIFFICULTY_1_TARGET / difficulty)
    max_target = 2**256 - 1
    return min(target, max_target)

def handle_sigint(signum, frame):
    if not g_sigint_shutdown.is_set():
        # No direct print needed, logger handles console output
        logger.warning("SIGINT received, initiating shutdown...")
        g_sigint_shutdown.set()
        with g_new_job_available: g_new_job_available.notify_all()
        g_connection_lost.set()
        close_socket()

def connect_pool() -> socket.socket | None:
    host = g_config["pool_host"]; port = g_config["pool_port"]
    logger.info(f"Resolving {host}:{port}...")
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info: logger.error(f"Could not resolve {host}"); return None
        sock = None; last_error = None
        for res in addr_info:
            af, socktype, proto, _, sa = res
            try:
                sock = socket.socket(af, socktype, proto); sock.settimeout(10)
                logger.info(f"Attempting connect to {sa[0]}:{sa[1]}...")
                sock.connect(sa); sock.settimeout(None); return sock
            except socket.error as e: last_error = e; logger.warning(f"Connect attempt failed to {sa[0]}: {e}")
            except Exception as e: last_error = e; logger.warning(f"Connect attempt failed to {sa[0]} (non-socket error): {e}")
            if sock: sock.close(); sock = None
        logger.error(f"Failed to connect to any resolved address for {host}:{port}. Last error: {last_error}"); return None
    except socket.gaierror as e: logger.error(f"DNS resolution failed for {host}: {e}"); return None
    except Exception as e: logger.error(f"Unexpected error during connect_pool: {e}"); return None

def close_socket():
    global g_sock
    with g_sock_lock:
        if g_sock:
            logger.debug(f"Closing socket FD {g_sock.fileno()}")
            try: g_sock.shutdown(socket.SHUT_RDWR)
            except socket.error: pass
            try: g_sock.close()
            except socket.error: pass
            g_sock = None

def send_json_rpc(sock: socket.socket, method: str, params: list, req_id: int) -> bool:
    if not sock: logger.error("send_json_rpc attempted on null socket."); return False
    try:
        payload = {"id": req_id, "method": method, "params": params}
        message = json.dumps(payload) + "\n"
        logger.debug(f"Sending: {message.strip()}")
        sock.sendall(message.encode('utf-8')); return True
    except socket.error as e: logger.error(f"Socket error sending JSON RPC ({method}): {e}")
    except Exception as e: logger.error(f"Error sending JSON RPC ({method}): {e}")
    # If sending fails, signal connection loss
    g_connection_lost.set();
    with g_new_job_available: g_new_job_available.notify_all()
    close_socket(); return False

# --- Subscribe Thread ---
def subscribe_thread_func():
    global g_shares_accepted, g_shares_rejected, g_current_height
    thread_name = threading.current_thread().name
    logger.info("Subscribe thread started.")
    receive_buffer = b""
    message_id_counter = 1
    current_sock = None

    with g_sock_lock:
        current_sock = g_sock
        if current_sock:
             try:
                 current_sock.setblocking(False) # Use non-blocking for select()
             except socket.error as e:
                 logger.error(f"Failed to set socket non-blocking: {e}")
                 g_connection_lost.set() # Can't proceed if this fails
                 current_sock = None # Mark as unusable

    if not current_sock:
         logger.error("Subscribe thread started with no valid/usable socket.")
         # Ensure main loop knows connection is lost if socket setup failed
         g_connection_lost.set()
         with g_new_job_available: g_new_job_available.notify_all()
         return

    subscribed = False
    authorized = False
    sub_id = -1
    auth_id = -1

    # Initial subscribe/authorize sequence
    try:
        message_id_counter = 1
        sub_id = message_id_counter; message_id_counter += 1
        auth_id = message_id_counter; message_id_counter += 1

        logger.info(f"Sending subscribe request (ID {sub_id})...")
        if not send_json_rpc(current_sock, "mining.subscribe", ["SimplePythonMiner/0.1.2"], sub_id):
             raise ConnectionError("Failed to send subscribe") # Raise to exit thread

        logger.info(f"Sending authorize request (ID {auth_id})...")
        if not send_json_rpc(current_sock, "mining.authorize", [g_config["wallet_address"], g_config["pool_password"]], auth_id):
            raise ConnectionError("Failed to send authorize") # Raise to exit thread

        logger.info("Waiting for pool responses/notifications...")

    except ConnectionError as e:
         logger.error(f"Initial connection setup failed: {e}")
         # Flags/socket closure handled by send_json_rpc or connect_pool
         return # Exit thread

    # --- Receive Loop using select() ---
    while not g_sigint_shutdown.is_set() and not g_connection_lost.is_set():
        readable = []
        exceptional = []
        with g_sock_lock:
            if not g_sock: # Check if socket closed by another thread
                logger.warning("Socket closed externally, ending subscribe loop.")
                g_connection_lost.set(); break
            try:
                # Check socket status with timeout
                readable, _, exceptional = select.select([current_sock], [], [current_sock], 1.0)
            except ValueError: # Socket might have been closed between lock release and select
                logger.warning("Socket closed before select() call.")
                g_connection_lost.set(); break
            except Exception as e:
                logger.error(f"Error during select(): {e}")
                g_connection_lost.set(); break

        if exceptional: logger.error("Socket exceptional condition detected."); g_connection_lost.set(); break

        if readable:
            try:
                chunk = current_sock.recv(8192)
                if not chunk:
                    logger.warning(f"Pool disconnected FD {current_sock.fileno()} (read 0 bytes).")
                    g_connection_lost.set(); break
                receive_buffer += chunk

                while b'\n' in receive_buffer:
                    line, receive_buffer = receive_buffer.split(b'\n', 1)
                    line = line.strip()
                    if not line: continue
                    logger.debug(f"Received raw: {line.decode('utf-8', errors='replace')}")
                    try:
                        data = json.loads(line)
                        msg_id = data.get('id'); method = data.get('method'); result = data.get('result'); error_info = data.get('error')

                        # --- Process Responses ---
                        if msg_id is not None:
                            if error_info:
                                logger.error(f"Pool error response ID {msg_id}: {error_info}")
                                if msg_id == sub_id: logger.critical("SUBSCRIBE FAILED (Pool Error)."); g_connection_lost.set(); break
                                if msg_id == auth_id: logger.critical(f"AUTHORIZATION FAILED: {error_info}. Check wallet/password."); g_connection_lost.set(); break
                                if isinstance(msg_id, int) and msg_id >= 100:
                                     logger.warning(f"Share REJECTED by pool (ID {msg_id}): {error_info}")
                                     with g_status_lock: g_shares_rejected += 1
                            elif result is not None or 'result' in data:
                                if msg_id == sub_id:
                                    if isinstance(result, list) and len(result) >= 3:
                                        e1_hex = result[1]; e2_size = result[2]; e1_bytes = hex_to_bytes(e1_hex)
                                        if e1_bytes is not None and isinstance(e2_size, int):
                                            with g_new_job_available:
                                                g_job_data["extranonce1"] = e1_bytes
                                                g_job_data["extranonce2_size"] = e2_size
                                            logger.info(f"Subscribe successful. E1: {e1_hex} ({len(e1_bytes)}B), E2Size: {e2_size}")
                                            subscribed = True
                                        else: logger.error(f"Invalid subscribe response format (E1/E2Size): {result}"); g_connection_lost.set(); break
                                    else: logger.error(f"Invalid subscribe response structure: {result}"); g_connection_lost.set(); break
                                elif msg_id == auth_id:
                                    auth_ok = result is True or result is None
                                    if auth_ok: logger.info("Authorization successful."); authorized = True
                                    else: logger.critical("AUTHORIZATION FAILED (result false/non-null). Check wallet/password."); g_connection_lost.set(); break
                                elif isinstance(msg_id, int) and msg_id >= 100:
                                    share_accepted = result is True or result is None
                                    if share_accepted: logger.info(f"Share accepted by pool (ID {msg_id})."); g_shares_accepted += 1
                                    else: logger.warning(f"Share likely rejected by pool (ID {msg_id}). Result: {result}"); g_shares_rejected += 1
                                else: logger.warning(f"Received success result for unexpected ID: {msg_id}")
                            else: logger.warning(f"Response ID {msg_id} with no 'result'/'error' field.")

                        # --- Process Notifications ---
                        elif method:
                            params = data.get('params', [])
                            if method == 'mining.notify':
                                if not subscribed or not authorized: logger.warning("Ignoring mining.notify before sub/auth complete."); continue
                                if len(params) >= 9:
                                    job_id, ph_hex, cb1_hex, cb2_hex, mb_hex_list, ver_hex, nbits_hex, ntime_hex, clean = params[:9]
                                    # Add DEBUG log to see raw nbits hex string from pool
                                    logger.debug(f"Job {job_id}: Received nbits_hex='{nbits_hex}'")
                                    ph_bytes = hex_to_bytes(ph_hex); cb1_bytes = hex_to_bytes(cb1_hex); cb2_bytes = hex_to_bytes(cb2_hex)
                                    mb_bytes_list = [hex_to_bytes(h) for h in mb_hex_list]
                                    ver_bytes = hex_to_bytes(ver_hex); nbits_bytes = hex_to_bytes(nbits_hex); ntime_bytes = hex_to_bytes(ntime_hex)

                                    # Check for conversion errors BEFORE calculating int values
                                    required_bytes = [ph_bytes, cb1_bytes, cb2_bytes, ver_bytes, nbits_bytes, ntime_bytes]
                                    if None in required_bytes or None in mb_bytes_list:
                                        logger.error(f"Failed to convert hex in mining.notify job {job_id}. Discarding. Check previous ERROR logs for bad hex.")
                                        continue # Skip this job if any hex failed

                                    if len(ph_bytes) != 32 or any(len(mb) != 32 for mb in mb_bytes_list if mb):
                                        logger.error(f"Incorrect hash length in mining.notify job {job_id}. Discarding.")
                                        continue

                                    # Convert BE hex bytes to host integer (usually LE host)
                                    try:
                                        version_int = int.from_bytes(ver_bytes, 'big')
                                        nbits_int   = int.from_bytes(nbits_bytes, 'big') # Parsed as big-endian number
                                        ntime_int   = int.from_bytes(ntime_bytes, 'big')
                                    except Exception as e:
                                         logger.error(f"Error converting version/nbits/ntime bytes to int for job {job_id}: {e}")
                                         continue

                                    # Store nbits value as parsed (big-endian int) for later conversion to LE for difficulty calc
                                    # Let's adjust: Store the nbits value intended for the block header (usually LE on wire, BE hex in stratum)
                                    # Standard nbits in stratum is BE hex. Parsing with int.from_bytes(bytes.fromhex(hex_str), 'big') gives the numerical value.
                                    # For difficulty calculation, we need the LE representation of this numerical value.
                                    # Let's store the numerical value (nbits_int) and convert to LE inside calculate_difficulty.
                                    # *** Correction: The `calculate_difficulty_from_nbits` function expects the host's little-endian integer representation.
                                    # So, we need to convert the big-endian value `nbits_int` to little-endian.
                                    nbits_le_host_int = int.from_bytes(nbits_int.to_bytes(4, 'big'), 'little')

                                    prevhash_le_bytes = reverse_bytes(ph_bytes)
                                    merkle_branch_be_bytes = mb_bytes_list # Store as received (BE bytes)

                                    net_diff = calculate_difficulty_from_nbits(nbits_le_host_int) # Use LE representation

                                    with g_new_job_available:
                                        is_new_block = g_job_data["prevhash"] != prevhash_le_bytes
                                        old_job_id = g_job_data["job_id"]
                                        g_job_data.update({
                                            "job_id": job_id, "prevhash": prevhash_le_bytes,
                                            "coinb1": cb1_bytes, "coinb2": cb2_bytes,
                                            "merkle_branch": merkle_branch_be_bytes,
                                            "version": version_int,
                                            "nbits": nbits_le_host_int, # Store LE host int
                                            "ntime": ntime_int,
                                            "clean_jobs": bool(clean)
                                        })
                                        g_new_job_available.notify_all()

                                    if is_new_block and old_job_id is not None:
                                        if g_current_height < 0: g_current_height = 1 # Estimate starts
                                        else: g_current_height += 1
                                        logger.info(f"[*] New Block ~{g_current_height}. Job: {job_id} (Clean:{clean}, NetDiff:{net_diff:.3e})")
                                    else:
                                        logger.info(f"New Job: {job_id} (Clean:{clean}, NetDiff:{net_diff:.3e})") # Log NetDiff here too

                                else: logger.warning(f"Received mining.notify with wrong number of params: {len(params)}")

                            elif method == 'mining.set_difficulty':
                                if len(params) >= 1:
                                    pool_difficulty = params[0]
                                    if isinstance(pool_difficulty, (int, float)) and pool_difficulty > 0:
                                         new_target = calculate_target_from_difficulty(float(pool_difficulty))
                                         with g_new_job_available: g_job_data["share_target"] = new_target
                                         actual_share_diff = calculate_difficulty_from_target(new_target)
                                         # Shorten target display in log
                                         target_hex = f"{new_target:064x}"
                                         short_target_hex = f"{target_hex[:6]}...{target_hex[-6:]}" if len(target_hex) > 12 else target_hex
                                         logger.info(f"Pool difficulty set to: {pool_difficulty:.1f} -> Share Target: {short_target_hex} (Share Diff: {actual_share_diff:.1f})")
                                    else: logger.warning(f"Ignoring invalid difficulty value: {pool_difficulty}")
                                else: logger.warning("Received mining.set_difficulty with no params.")
                            else: logger.warning(f"Received unknown notification method: {method}")
                        else: logger.warning(f"Received message with no ID and no method: {data}")

                    except json.JSONDecodeError: logger.error(f"JSON decode error for line: {line.decode('utf-8', errors='replace')}")
                    except Exception as e: logger.exception(f"Error processing message: {line.decode('utf-8', errors='replace')}")

            except socket.error as e:
                if e.errno != socket.errno.EAGAIN and e.errno != socket.errno.EWOULDBLOCK:
                    logger.error(f"Socket error receiving data: {e}")
                    g_connection_lost.set(); break
            except Exception as e: logger.exception("Unexpected error processing received data."); g_connection_lost.set(); break

        if g_connection_lost.is_set() or g_sigint_shutdown.is_set(): break # Exit loop if flags set

    # --- End of Receive Loop ---
    logger.info("Subscribe thread finishing.")
    if g_connection_lost.is_set(): close_socket()
    with g_new_job_available: g_new_job_available.notify_all()


# --- Miner Thread ---
def miner_thread_func(thread_id: int, num_threads: int):
    """Hashes potential blocks and submits shares."""
    thread_name = threading.current_thread().name
    logger.info(f"Miner thread {thread_id} started.")
    local_hashes = 0
    last_hash_report_time = time.monotonic()

    while not g_sigint_shutdown.is_set():
        job = None; target = 0; e1 = b''; e2_size = 4; current_job_id = None

        with g_new_job_available:
            while not g_sigint_shutdown.is_set() and not g_connection_lost.is_set() and g_job_data["job_id"] is None:
                g_new_job_available.wait(timeout=1.0)
            if g_sigint_shutdown.is_set() or g_connection_lost.is_set(): break # Exit thread loop
            if g_job_data["job_id"] is None or not g_job_data["extranonce1"] or g_job_data["share_target"] == 0:
                # logger.debug(f"Miner {thread_id} woke up but job invalid/incomplete. Re-waiting.")
                continue # Go back to waiting

            # Copy job data under lock
            job = g_job_data.copy(); target = g_job_data["share_target"]
            e1 = g_job_data["extranonce1"]; e2_size = g_job_data["extranonce2_size"]
            current_job_id = job["job_id"]

        logger.debug(f"Miner {thread_id} starting job {current_job_id} (E2Size: {e2_size}, Tgt: {target:064x})")
        job_abandoned_by_thread = False
        extranonce2 = bytearray(e2_size)
        if e2_size > 0:
            start_val_limited = thread_id % (2**(8*e2_size))
            start_val_bytes = start_val_limited.to_bytes(e2_size, 'little', signed=False)
            extranonce2 = bytearray(start_val_bytes)

        e2_stride = num_threads
        e2_iterations = 0
        MAX_E2_ITERATIONS = 2**(8*e2_size) if 0 < e2_size <= 4 else (2**32 if e2_size > 4 else 1)
        if e2_size == 0: extranonce2 = b""; MAX_E2_ITERATIONS = 1

        # --- Extranonce2 Iteration Loop ---
        while e2_iterations < MAX_E2_ITERATIONS and not job_abandoned_by_thread and not g_sigint_shutdown.is_set() and not g_connection_lost.is_set():
            if e2_iterations > 0: # Increment E2 after the first iteration
                i = 0; carry = e2_stride
                while i < e2_size and carry > 0:
                    new_val = int(extranonce2[i]) + carry
                    extranonce2[i] = new_val & 0xFF; carry = new_val >> 8; i += 1
                if carry > 0 and i >= e2_size:
                    logger.warning(f"Miner {thread_id} exhausted its extranonce2 range for job {current_job_id}.")
                    break # Exit E2 loop

            e2_current = bytes(extranonce2) # Use immutable bytes for hashing

            # --- Calculate Merkle Root ---
            try:
                coinbase_tx = job["coinb1"] + e1 + e2_current + job["coinb2"]
                coinbase_hash_be = sha256d(coinbase_tx); current_hash_be = coinbase_hash_be
                for branch_be in job["merkle_branch"]:
                    current_hash_be = sha256d(current_hash_be + branch_be)
                merkle_root_le = reverse_bytes(current_hash_be)
            except Exception as e:
                logger.exception(f"Miner {thread_id} error calculating Merkle root for job {current_job_id}.")
                job_abandoned_by_thread = True
                continue # Skip to next E2 iteration (or job wait if loop breaks)

            # --- Construct Block Header Template (without nonce) ---
            try:
                version_bytes_le = job["version"].to_bytes(4, 'little')
                prevhash_bytes_le = job["prevhash"] # Already LE bytes
                ntime_bytes_le = job["ntime"].to_bytes(4, 'little')
                # Use the stored nbits (already LE host int)
                nbits_bytes_le = job["nbits"].to_bytes(4, 'little')
                header_template_le = version_bytes_le + prevhash_bytes_le + merkle_root_le + ntime_bytes_le + nbits_bytes_le
                if len(header_template_le) != 76:
                     raise ValueError("Header template length != 76")
            except Exception as e:
                logger.exception(f"Miner {thread_id} error constructing header template for job {current_job_id}.")
                job_abandoned_by_thread = True
                continue # Skip to next E2 iteration

            # --- Nonce Iteration Loop ---
            nonce = 0; NONCE_MAX = 0xFFFFFFFF
            while nonce <= NONCE_MAX:
                # --- Periodic check for new job/shutdown/disconnect ---
                if (nonce & 0xFFFF) == 0: # Check every 65536 nonces
                    if g_sigint_shutdown.is_set() or g_connection_lost.is_set():
                        job_abandoned_by_thread = True; break # Exit nonce loop
                    with g_new_job_available: # Check job/target under lock
                        if g_job_data["job_id"] != current_job_id: # New job arrived
                            job_abandoned_by_thread = True; break # Exit nonce loop
                        new_target = g_job_data["share_target"]
                        if new_target != target: # Target updated
                            target = new_target
                        if target == 0: # Target became invalid?
                            logger.warning(f"Miner {thread_id} target became 0 mid-job {current_job_id}. Abandoning.")
                            job_abandoned_by_thread = True; break # Exit nonce loop

                    # --- Report hash count periodically ---
                    current_time = time.monotonic()
                    if current_time - last_hash_report_time >= 1.0: # Report approx every second
                        hashes_done = local_hashes
                        local_hashes = 0 # Reset count *after* getting value
                        if hashes_done > 0:
                             with g_status_lock: # Acquire lock to update shared deque
                                 g_hash_counts.append((current_time, hashes_done))
                        last_hash_report_time = current_time # Update time after reporting

                # --- Construct full header and hash ---
                nonce_bytes_le = nonce.to_bytes(4, 'little')
                header_le = header_template_le + nonce_bytes_le
                block_hash_be = sha256d(header_le)
                block_hash_le = reverse_bytes(block_hash_be)
                local_hashes += 1 # Increment hash count *after* successful hash

                # --- Check hash against target ---
                hash_int = int.from_bytes(block_hash_le, 'little')
                if hash_int <= target:
                    # Found a share!
                    share_ntime_hex = job["ntime"].to_bytes(4,'big').hex()
                    share_nonce_hex = nonce.to_bytes(4,'big').hex()
                    share_e2_hex = bytes_to_hex(e2_current)

                    # Calculate difficulties for logging
                    net_diff = calculate_difficulty_from_nbits(job["nbits"]) # Use the nbits stored in the job
                    share_diff = calculate_difficulty_from_target(target)
                    network_target = calculate_target_from_difficulty(net_diff) if net_diff > 0 else (2**256-1)
                    meets_network = hash_int <= network_target
                    block_marker = " [BLOCK!]" if meets_network else ""

                    logger.info(f"SHARE FOUND! Job: {current_job_id} Nonce: 0x{nonce:08x} (Diff: {share_diff:.2f}){block_marker}")
                    # logger.debug(f"Share Details: H(BE)={bytes_to_hex(block_hash_be)} Tgt={target:064x} E2(LE)={share_e2_hex}")

                    # --- Submit Share ---
                    current_sock = None
                    with g_sock_lock: current_sock = g_sock # Check socket under lock
                    if current_sock:
                        submit_id = int(time.time() * 1000) + thread_id # Simple unique-ish ID
                        send_json_rpc(current_sock, "mining.submit", [
                            g_config["wallet_address"], current_job_id,
                            share_e2_hex, share_ntime_hex, share_nonce_hex
                        ], submit_id)
                    else:
                        # Socket is closed, cannot submit
                        logger.error("Cannot submit share, socket is closed.")
                        g_connection_lost.set() # Ensure connection state is updated
                        with g_new_job_available: # Notify other threads waiting
                            g_new_job_available.notify_all()

                    # Stop working on this E2 value after finding a share
                    job_abandoned_by_thread = True
                    break # Exit nonce loop

                nonce += 1
            # --- End Nonce Loop ---

            # --- After nonce loop (natural end or break): Check flags and report remaining hashes ---
            if job_abandoned_by_thread or g_sigint_shutdown.is_set() or g_connection_lost.is_set():
                 # If loop was broken by abandon/shutdown/disconnect, exit E2 loop too
                 break

            # *** CORRECTED BLOCK START ***
            # Report any remaining hashes accumulated during the last part of the nonce loop for this E2
            if local_hashes > 0:
                with g_status_lock: # Acquire lock to update shared deque
                     g_hash_counts.append((time.monotonic(), local_hashes))
                local_hashes = 0 # Reset count *after* reporting
            # *** CORRECTED BLOCK END ***

            e2_iterations += 1 # Move to next E2 value
        # --- End Extranonce2 Loop ---

        # Loop will naturally restart to wait for a new job if E2 loop finished
        # If loop was broken by flags, the outer `while not g_sigint_shutdown.is_set():` check will handle exit

    # --- Miner Thread Exit ---
    logger.info(f"Miner thread {thread_id} finished.")
    # Final hash report before exiting
    # *** CORRECTED BLOCK START ***
    if local_hashes > 0:
        with g_status_lock: # Acquire lock to update shared deque
            g_hash_counts.append((time.monotonic(), local_hashes))
    # *** CORRECTED BLOCK END ***
# --- Status Thread ---
def status_thread_func():
    """Periodically logs status."""
    thread_name = threading.current_thread().name
    logger.info("Status thread started.")
    global g_last_status_time # No need for g_total_hashes_reported here

    while not g_sigint_shutdown.is_set():
        now = time.monotonic()
        if now - g_last_status_time >= STATUS_LOG_INTERVAL_SECONDS:
            rate = 0.0; duration = 0; total_hashes_in_window = 0

            with g_status_lock:
                window_duration = 60.0; window_start_time = now - window_duration
                valid_entries = [(t, h) for t, h in g_hash_counts if t >= window_start_time]
                if valid_entries:
                    first_ts = valid_entries[0][0]; last_ts = valid_entries[-1][0]
                    total_hashes_in_window = sum(h for _, h in valid_entries)
                    if len(valid_entries) > 1: duration = last_ts - first_ts
                    elif len(valid_entries) == 1: duration = max(now - first_ts, 1.0)
                    if duration > 0: rate = total_hashes_in_window / duration
                    while len(g_hash_counts) > 0 and g_hash_counts[0][0] < window_start_time: g_hash_counts.popleft()

            display_rate = rate; unit = "H/s"
            if rate >= 1e9: display_rate = rate / 1e9; unit = "GH/s"
            elif rate >= 1e6: display_rate = rate / 1e6; unit = "MH/s"
            elif rate >= 1e3: display_rate = rate / 1e3; unit = "kH/s"

            local_height = g_current_height # Read directly
            local_job_id = None; local_nbits = 0; local_share_target = 0
            local_accepted = 0; local_rejected = 0

            with g_new_job_available: # Lock for job data
                 local_job_id = g_job_data["job_id"]
                 local_nbits = g_job_data["nbits"] # This is LE host int
                 local_share_target = g_job_data["share_target"]
            with g_status_lock: # Lock for share counts
                 local_accepted = g_shares_accepted
                 local_rejected = g_shares_rejected

            net_diff = calculate_difficulty_from_nbits(local_nbits) if local_nbits else 0.0
            share_diff = calculate_difficulty_from_target(local_share_target) if local_share_target else 0.0
            height_display = f"~{local_height}" if local_height > 0 else "N/A" # Use N/A initially

            status_str = (f"H: {height_display} | NetD: {net_diff:.3e} | ShareD: {share_diff:.1f} | "
                          f"Rate: {display_rate:.2f} {unit} | A/R: {local_accepted}/{local_rejected}")

            # *** Log the status - this now handles console output too ***
            logger.info(f"[STATUS] {status_str}")
            # *** Removed the direct print() call ***

            g_last_status_time = now

        shutdown_detected = g_sigint_shutdown.wait(timeout=1.0)
        if shutdown_detected: break

    logger.info("Status thread finished.")

# --- Main Execution ---
def main():
    global g_sock, g_current_height
    logger.info("Miner v0.1.2")
    #print("Miner v0.1.2 ") # Version bump

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    if not load_config():
        print("Exiting due to configuration errors.", file=sys.stderr)
        sys.exit(1)

    logger.info("--------------------------------------------------")
    logger.info("Miner starting with configuration:")
    for key, value in g_config.items():
         log_value = "(set)" if key == "pool_password" and value else value
         logger.info(f"  {key.replace('_', ' ').title()}: {log_value}")
    logger.info("--------------------------------------------------")
    logger.info(f"Console log level: {logging.getLevelName(console_handler.level)}")
    if file_handler: logger.info(f"File log level: {logging.getLevelName(file_handler.level)}")

    threads = []
    while not g_sigint_shutdown.is_set():
        logger.info(f"Attempting connection to pool {g_config['pool_host']}:{g_config['pool_port']}...")
        g_connection_lost.clear()
        with g_status_lock: g_hash_counts.clear(); g_shares_accepted = 0; g_shares_rejected = 0
        with g_new_job_available:
             g_job_data["job_id"] = None; g_job_data["share_target"] = calculate_target_from_difficulty(1.0)
             g_job_data["extranonce1"] = None; g_current_height = -1 # Reset height on reconnect

        new_sock = connect_pool()

        if new_sock:
            with g_sock_lock: g_sock = new_sock
            logger.info(f"Connection successful (FD {g_sock.fileno()}). Starting threads...")

            threads = []
            sub_thread = threading.Thread(target=subscribe_thread_func, name="SubscribeThread", daemon=True)
            sub_thread.start(); threads.append(sub_thread)
            time.sleep(0.1) # Small delay potentially helps stabilize thread start

            status_thread = threading.Thread(target=status_thread_func, name="StatusThread", daemon=True)
            status_thread.start(); threads.append(status_thread)
            time.sleep(0.1)

            num_miner_threads = g_config['threads']
            for i in range(num_miner_threads):
                miner_thread = threading.Thread(target=miner_thread_func, args=(i, num_miner_threads), name=f"MinerThread-{i}", daemon=True)
                miner_thread.start(); threads.append(miner_thread)

            while not g_sigint_shutdown.is_set() and not g_connection_lost.is_set():
                g_connection_lost.wait(timeout=5.0)

            if g_sigint_shutdown.is_set(): logger.info("Main loop notified of shutdown.")
            elif g_connection_lost.is_set(): logger.warning("Pool connection lost. Preparing to reconnect...")

            close_socket()
            logger.info("Waiting for threads to finish...")
            join_timeout = 2.0
            for t in threads: t.join(timeout=join_timeout); # Removed is_alive check log noise
            threads = []
            logger.info("Threads stopped/joined.")

            if g_sigint_shutdown.is_set(): break
            logger.info(f"Waiting {RECONNECT_DELAY_SECONDS}s before reconnecting...")
            reconnect_wait_interrupted = g_sigint_shutdown.wait(timeout=RECONNECT_DELAY_SECONDS)
            if reconnect_wait_interrupted: logger.info("Shutdown signal received during reconnect wait."); break

        else: # Connection failed
            logger.error(f"Connection failed. Retrying in {RECONNECT_DELAY_SECONDS} seconds...")
            fail_wait_interrupted = g_sigint_shutdown.wait(timeout=RECONNECT_DELAY_SECONDS)
            if fail_wait_interrupted: logger.info("Shutdown signal received during connection retry wait."); break

    # --- Final Cleanup ---
    logger.info("Miner shutting down.")
    # Final message to console might be useful after logging stops
    print(f"\n\033[92mMiner exiting...\033[0m", file=sys.stderr)
    close_socket()
    # Join lingering threads if any (less critical now threads are daemon)
    # ... (join logic can be simplified or removed if daemons are reliable) ...
    logger.info("----------------- Miner Exited -----------------")
    logging.shutdown() # Flush and close handlers

if __name__ == "__main__":
    main()
