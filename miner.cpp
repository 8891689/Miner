// miner.cpp
// g++ miner.cpp sha256.cpp sha256_sse.cpp -o miner -O3 -march=native -lcurl -ljson-c -pthread -lm -lgmp
//author：8891689
//Assist in creation：gemini
#include "sha256.h"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdarg>
#include <csignal>
#include <thread>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <locale>
#include <cmath>
#include <limits>
#include <set>
#include <numeric> 

#include <gmp.h>

// --- Platform Specific Includes ---
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <intrin.h> // For __cpuid
    #pragma comment(lib, "Ws2_32.lib")
#else // POSIX
    #include <unistd.h>
    #include <netdb.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <cerrno>
    #include <cpuid.h> // For __get_cpuid
    #define closesocket close
    typedef int SOCKET;
    const int INVALID_SOCKET = -1;
    const int SOCKET_ERROR = -1;
#endif

// --- Endianness Check/Helpers ---
#if defined(__linux__) || defined(__APPLE__)
    #include <endian.h>
    #define local_htole32(x) htole32(x)
    #define local_htobe32(x) htobe32(x)
    #define local_be32toh(x) be32toh(x)
    #define local_le32toh(x) le32toh(x)
    #define local_htobe64(x) htobe64(x)
    #define local_be64toh(x) be64toh(x)
#elif defined(_WIN32) && defined(_MSC_VER) // MSVC
    #include <stdlib.h>
    #define local_htole32(x) ((uint32_t)(x))
    #define local_le32toh(x) ((uint32_t)(x))
    #define local_htobe32(x) _byteswap_ulong(x)
    #define local_be32toh(x) _byteswap_ulong(x)
    #define local_htobe64(x) _byteswap_uint64(x)
    #define local_be64toh(x) _byteswap_uint64(x)
#elif defined(_WIN32) // MinGW
    #include <winsock2.h> // For htonl, ntohl
    #include <stdlib.h>
    #define local_htole32(x) ((uint32_t)(x))
    #define local_le32toh(x) ((uint32_t)(x))
    #define local_htobe32(x) htonl(x)
    #define local_be32toh(x) ntohl(x)
    // Manual 64-bit swap for MinGW if htonll/ntohll not available
    inline uint64_t _byteswap_uint64_manual(uint64_t val) { return ( ( val << 56 ) & 0xff00000000000000ULL ) | ( ( val << 40 ) & 0x00ff000000000000ULL ) | ( ( val << 24 ) & 0x0000ff0000000000ULL ) | ( ( val << 8 ) & 0x000000ff00000000ULL ) | ( ( val >> 8 ) & 0x00000000ff000000ULL ) | ( ( val >> 24 ) & 0x0000000000ff0000ULL ) | ( ( val >> 40 ) & 0x000000000000ff00ULL ) | ( ( val >> 56 ) & 0x00000000000000ffULL ); }
    #ifndef htonll
        inline uint64_t htonll(uint64_t val) { return _byteswap_uint64_manual(val); }
        inline uint64_t ntohll(uint64_t val) { return _byteswap_uint64_manual(val); }
    #endif
    #define local_htobe64(x) htonll(x)
    #define local_be64toh(x) ntohll(x)
#else // Fallback
    #warning "Using manual byte swap fallback - check host endianness if issues arise"
    inline uint32_t _byteswap_ulong_manual(uint32_t val) { return ((val << 24)) | ((val << 8) & 0x00FF0000) | ((val >> 8) & 0x0000FF00) | ((val >> 24)); }
    inline uint64_t _byteswap_uint64_manual(uint64_t val) { return ( ( val << 56 ) & 0xff00000000000000ULL ) | ( ( val << 40 ) & 0x00ff000000000000ULL ) | ( ( val << 24 ) & 0x0000ff0000000000ULL ) | ( ( val << 8 ) & 0x000000ff00000000ULL ) | ( ( val >> 8 ) & 0x00000000ff000000ULL ) | ( ( val >> 24 ) & 0x0000000000ff0000ULL ) | ( ( val >> 40 ) & 0x000000000000ff00ULL ) | ( ( val >> 56 ) & 0x00000000000000ffULL ); }
    // Assume little-endian host for fallback if not WIN/LINUX/APPLE
    #define local_htole32(x) ((uint32_t)(x))
    #define local_le32toh(x) ((uint32_t)(x))
    #define local_htobe32(x) _byteswap_ulong_manual(x)
    #define local_be32toh(x) _byteswap_ulong_manual(x)
    #define local_htobe64(x) _byteswap_uint64_manual(x)
    #define local_be64toh(x) _byteswap_uint64_manual(x)
#endif

// External Libraries
#include <curl/curl.h>
#include <json-c/json.h>
//=======================================================================================

// --- Configuration Variables ---
std::string g_pool_host;
int         g_pool_port = 0;
std::string g_wallet_addr;
std::string g_pool_password = "x";
std::string g_log_file = "miner.log";
int         g_threads = 0;

#define RECONNECT_DELAY_SECONDS 5
#define STATUS_LOG_INTERVAL_SECONDS 30
#define CONFIG_FILE "config.json"
//=======================================================================================
// ANSI colors
const char* C_RED    = "\x1b[31m";
const char* C_GREEN  = "\x1b[32m";
const char* C_YELLOW = "\x1b[33m";
const char* C_MAG    = "\x1b[35m";
const char* C_CYAN   = "\x1b[36m";
const char* C_RESET  = "\x1b[0m";

// --- Global State ---
std::atomic<bool> g_sigint_shutdown(false);
std::atomic<SOCKET> g_sockfd(INVALID_SOCKET); // Atomic socket descriptor
std::mutex        g_job_mutex;              // Protects job data AND nbits/extranonce size
bool              g_new_job_available = false;
std::condition_variable g_new_job_cv;
std::atomic<bool> g_connection_lost(false);

// Hashrate Calculation State
//std::vector<std::atomic<uint64_t>> g_thread_hash_counts; // Global declaration, initialized in main
std::vector<std::atomic<uint64_t>> g_thread_hash_counts; // <--- 改為只聲明類型
std::atomic<uint64_t> g_total_hashes_reported(0);
std::atomic<double>   g_aggregated_hash_rate(0.0);
std::chrono::steady_clock::time_point g_last_aggregated_report_time;

// --- Stratum Job Data (Protected by g_job_mutex) ---
std::string       g_job_id;
std::vector<unsigned char> g_prevhash_bin; // Little Endian binary
std::vector<unsigned char> g_coinb1_bin;
std::vector<unsigned char> g_coinb2_bin;
std::vector<std::vector<unsigned char>> g_merkle_branch_bin_be; // Big Endian binary (as received)
uint32_t          g_version_le = 0; // Little Endian host format
uint32_t          g_nbits_le = 0;   // Little Endian host format (NETWORK nBits)
uint32_t          g_ntime_le = 0;   // Little Endian host format
bool              g_clean_jobs = false;

// --- Stratum Subscribe Data (Protected by g_job_mutex) ---
std::vector<unsigned char> g_extranonce1_bin;
size_t            g_extranonce2_size = 4; // Default, updated by subscribe response

// --- Other Globals ---
std::atomic<long> g_current_height(-1); // Block height, updated from API or job

// Store 256-bit share target using GMP (Protected by g_share_target_mutex)
mpz_t             g_share_target;
std::mutex        g_share_target_mutex;

//=======================================================================================
// --- Forward Declarations ---
void miner_func(int thread_id, int num_threads); // Make sure this is declared
void subscribe_func();
std::string bin_to_hex(const unsigned char *in, size_t len);
std::string bin_to_hex(const std::vector<unsigned char>& bin);
bool hex_to_bin(const std::string& hex, std::vector<unsigned char>& bin);
bool hex_to_bin(const std::string& hex, unsigned char* bin_ptr, size_t bin_size);
void log_msg(const char *fmt, ...);
std::string timestamp_us();
bool is_hash_less_than_target(const unsigned char hash_le[32], uint32_t nbits_le); // For network target check
bool is_hash_less_or_equal_target_gmp(const unsigned char hash_le[32], const mpz_t target_ro); // GMP comparison
std::vector<unsigned char> calculate_simplified_merkle_root_le(
    const std::vector<unsigned char>& coinb1_bin_param,
    const std::vector<unsigned char>& extranonce1_bin_param,
    const std::vector<unsigned char>& extranonce2_bin_param,
    const std::vector<unsigned char>& coinb2_bin_param,
    const std::vector<std::vector<unsigned char>>& merkle_branch_be_list_param);
double calculate_difficulty(uint32_t nbits_le); // Difficulty from nBits
double calculate_difficulty_from_target(const mpz_t target_ro); // Difficulty from GMP target
void log_periodic_status();
bool load_config();
bool check_cpu_features();
void increment_extranonce2(std::vector<unsigned char>& en2);
std::string uint32_to_hex_be(uint32_t val_le);


// --- Helper Functions ---

// CPU Feature Check
bool check_cpu_features() {
    bool has_sse2 = false; bool has_ssse3 = false;
#ifdef _WIN32
    int cpuInfo[4]; __cpuid(cpuInfo, 1); has_sse2 = (cpuInfo[3] & (1 << 26)) != 0; has_ssse3 = (cpuInfo[2] & (1 << 9)) != 0;
#else
    unsigned int eax, ebx, ecx, edx; if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) { has_sse2 = (edx & (1 << 26)) != 0; has_ssse3 = (ecx & (1 << 9)) != 0; } else { log_msg("[ERROR] __get_cpuid failed."); return false; }
#endif
    if (!has_sse2) { log_msg("[ERROR] CPU does not support SSE2."); fprintf(stderr, "%s[ERROR] SSE2 support required!%s\n", C_RED, C_RESET); }
    if (!has_ssse3) { log_msg("[ERROR] CPU does not support SSSE3."); fprintf(stderr, "%s[ERROR] SSSE3 support required!%s\n", C_RED, C_RESET); }
    if (has_sse2 && has_ssse3) { log_msg("[INFO] CPU supports required SSE2 and SSSE3 instructions."); fprintf(stdout, "[INFO] CPU Features: %sSSE2 OK%s, %sSSSE3 OK%s\n", C_GREEN, C_RESET, C_GREEN, C_RESET); return true; }
    else { return false; }
}

// Double SHA256
void sha256_double_be(const unsigned char* data, size_t len, unsigned char* output32_be) {
    unsigned char first_hash_be[32];
    sha256(const_cast<unsigned char*>(data), len, first_hash_be);
    sha256(first_hash_be, 32, output32_be);
}

// Calculate Merkle Root
std::vector<unsigned char> calculate_simplified_merkle_root_le(
    const std::vector<unsigned char>& coinb1_bin_param, const std::vector<unsigned char>& extranonce1_bin_param,
    const std::vector<unsigned char>& extranonce2_bin_param, const std::vector<unsigned char>& coinb2_bin_param,
    const std::vector<std::vector<unsigned char>>& merkle_branch_be_list_param)
{
    // Construct full coinbase transaction binary
    std::vector<unsigned char> coinbase_tx_bin = coinb1_bin_param;
    coinbase_tx_bin.insert(coinbase_tx_bin.end(), extranonce1_bin_param.begin(), extranonce1_bin_param.end());
    coinbase_tx_bin.insert(coinbase_tx_bin.end(), extranonce2_bin_param.begin(), extranonce2_bin_param.end());
    coinbase_tx_bin.insert(coinbase_tx_bin.end(), coinb2_bin_param.begin(), coinb2_bin_param.end());

    // Double SHA256 the coinbase transaction -> Coinbase Hash (Big Endian)
    unsigned char current_hash_be[32];
    sha256_double_be(coinbase_tx_bin.data(), coinbase_tx_bin.size(), current_hash_be);

    // Combine with merkle branches
    for (const auto& branch_hash_be : merkle_branch_be_list_param) {
        unsigned char concat_be[64];
        memcpy(concat_be, current_hash_be, 32);             // Current hash (BE)
        memcpy(concat_be + 32, branch_hash_be.data(), 32); // Branch hash (BE)
        sha256_double_be(concat_be, sizeof(concat_be), current_hash_be); // Double SHA256 -> New current hash (BE)
    }

    // Final result (current_hash_be) is the Merkle Root in Big Endian.
    // Return it in Little Endian as needed for the block header.
    std::vector<unsigned char> merkle_root_le(current_hash_be, current_hash_be + 32);
    std::reverse(merkle_root_le.begin(), merkle_root_le.end());
    return merkle_root_le;
}

// Check hash against nBits target (for network block check - mostly for logging)
bool is_hash_less_than_target(const unsigned char hash_le[32], uint32_t nbits_le) {
    if (nbits_le == 0) { return false; } // Invalid nBits

    // Convert nBits (LE) to BE for easier parsing
    uint32_t nbits_be = local_htobe32(nbits_le);
    uint32_t exponent = (nbits_be >> 24) & 0xFF;
    uint32_t coefficient = nbits_be & 0x00FFFFFF;

    // Basic validation of nBits exponent
    if (exponent < 3 || exponent > 32) { return false; }

    // Calculate the index of the most significant byte of the target
    int target_msb_index = static_cast<int>(exponent) - 1; // 0-based index (0-31)

    // Compare hash (LE) with derived target (LE interpretation) byte by byte from MSB down
    for (int i = 31; i >= 0; --i) {
        unsigned char hash_byte = hash_le[i]; // Get hash byte (MSB first due to loop)
        unsigned char target_byte = 0;

        // Calculate the position of this byte relative to the target's MSB
        int shift = (target_msb_index - i) * 8;

        if (shift >= 0 && shift < 24) {
            // This byte falls within the coefficient range
            target_byte = (coefficient >> shift) & 0xFF;
        } else if (i > target_msb_index) {
             // This byte is more significant than the target's MSB, target byte is 0
             target_byte = 0;
        } else {
            // This byte is less significant than the target's coefficient bytes, target byte is 0
            target_byte = 0;
        }
        // Compare hash byte with target byte
        if (hash_byte < target_byte) return true;  // Hash is smaller
        if (hash_byte > target_byte) return false; // Hash is larger
    }
    // If all bytes are equal, hash is equal to target, which is not strictly less
    return false;
}

// Check hash (Little Endian binary) against 256-bit GMP target (Little Endian)
bool is_hash_less_or_equal_target_gmp(const unsigned char hash_le[32], const mpz_t target_ro) {
    mpz_t hash_mpz;
    mpz_init(hash_mpz);
    // Import the 32-byte hash (Little Endian) into a GMP integer.
    // Order=1 (Least Significant Word first -> byte in this case)
    // Endian=-1 (Little Endian machine representation of the bytes)
    // Nails=0 (use all bits of each byte)
    mpz_import(hash_mpz, 32, 1, sizeof(unsigned char), -1, 0, hash_le);

    // Compare hash <= target
    int cmp_result = mpz_cmp(hash_mpz, target_ro);

    mpz_clear(hash_mpz); // Clean up temporary GMP variable
    return (cmp_result <= 0); // Return true if hash is less than or equal to target
}

// Calculate difficulty from nBits (Little Endian)
double calculate_difficulty(uint32_t nbits_le) {
    if (nbits_le == 0) return 0.0;

    uint32_t nbits_be = local_htobe32(nbits_le);
    uint32_t exponent = (nbits_be >> 24) & 0xFF;
    uint32_t coefficient = nbits_be & 0x00FFFFFF;

    // Handle edge case of coefficient 0 (though unlikely for valid nBits)
    if (coefficient == 0) { return std::numeric_limits<double>::infinity(); }
    // Basic validation
    if (exponent < 3 || exponent > 32) return 0.0; // Invalid exponent

    // Difficulty 1 target (0x1d00ffff) values
    const double diff1_coeff = 0x00ffff; // Coefficient for difficulty 1
    const int diff1_exp = 0x1d;        // Exponent for difficulty 1

    // Calculate difficulty = target1 / target_current
    // target = coefficient * 2^(8*(exponent-3))
    // difficulty = (diff1_coeff * 2^(8*(diff1_exp-3))) / (coeff * 2^(8*(exp-3)))
    // difficulty = (diff1_coeff / coeff) * 2^(8*(diff1_exp - exp))
    const int current_exp_shift = 8 * (static_cast<int>(exponent) - 3);
    const int diff1_exp_shift = 8 * (diff1_exp - 3);

    // Use double for calculation to handle potential large/small numbers
    double difficulty = (diff1_coeff / static_cast<double>(coefficient)) * std::pow(2.0, diff1_exp_shift - current_exp_shift);
    return difficulty;
}

// Calculate difficulty from a 256-bit GMP target
double calculate_difficulty_from_target(const mpz_t target_ro) {
    mpz_t target1_mpz;
    mpf_t target1_f, target_f, diff_f; // Use floating point for division
    double difficulty = 0.0;

    // Initialize GMP variables
    // Difficulty 1 target: 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    mpz_init_set_str(target1_mpz, "00000000FFFF0000000000000000000000000000000000000000000000000000", 16);
    mpf_inits(target1_f, target_f, diff_f, NULL);

    try {
        // Convert targets to floating point
        mpf_set_z(target1_f, target1_mpz);
        mpf_set_z(target_f, target_ro); // Use the read-only input target

        // Calculate difficulty = target1 / target, avoid division by zero
        if (mpf_sgn(target_f) > 0) { // Check if target is positive
            mpf_div(diff_f, target1_f, target_f);
            difficulty = mpf_get_d(diff_f); // Get double value
        } else {
            // Target is zero or negative, difficulty is effectively infinite
             difficulty = std::numeric_limits<double>::infinity();
             log_msg("[WARN] calculate_difficulty_from_target: Target is non-positive.");
        }
    } catch(...) {
        log_msg("[ERROR] Exception during GMP difficulty calculation.");
        difficulty = 0.0; // Indicate error
    }

    // Clean up GMP variables
    mpz_clear(target1_mpz);
    mpf_clears(target1_f, target_f, diff_f, NULL);

    return difficulty;
}


// Get timestamp string with microseconds
std::string timestamp_us() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds);
    time_t seconds_t = seconds.count();
    std::tm now_tm = {};
#ifdef _WIN32
    localtime_s(&now_tm, &seconds_t);
#else
    localtime_r(&seconds_t, &now_tm); // POSIX thread-safe version
#endif
    std::stringstream ss;
    ss.imbue(std::locale::classic()); // Ensure '.' is used as decimal separator
    ss << std::put_time(&now_tm, "%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(6) << microseconds.count();
    return ss.str();
}

// Logging function (thread-safe)
std::mutex g_log_mutex;
void log_msg(const char *fmt, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    buffer[sizeof(buffer) - 1] = '\0'; // Ensure null termination

    std::string message = "[" + timestamp_us() + "] " + buffer;

    // Lock mutex for writing to file and stderr
    std::lock_guard<std::mutex> lock(g_log_mutex);
    try {
        std::ofstream log_stream(g_log_file, std::ios::app);
        if (log_stream) {
            log_stream << message << std::endl;
        } else {
            // Fallback to stderr if log file cannot be opened
            fprintf(stderr, "[!!! LOG FILE WRITE ERROR !!!] %s\n", message.c_str());
        }
    } catch (const std::exception& e) {
         fprintf(stderr, "[!!! LOG FILE EXCEPTION !!!] %s : %s\n", message.c_str(), e.what());
    } catch (...) {
         fprintf(stderr, "[!!! LOG FILE UNKNOWN EXCEPTION !!!] %s\n", message.c_str());
    }
    // We might still want to print to stderr even if logging fails, or vice-versa
    // Consider if duplicate logging is desired or if the file write is primary.
    // Currently, errors during file write are printed to stderr.
}

// Binary to Hex string conversion
std::string bin_to_hex(const unsigned char *in, size_t len) {
    if (!in || len == 0) return "";
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(in[i]);
    }
    return ss.str();
}
std::string bin_to_hex(const std::vector<unsigned char>& bin) {
    return bin_to_hex(bin.data(), bin.size());
}

// Hex string to binary vector conversion
bool hex_to_bin(const std::string& hex, std::vector<unsigned char>& bin) {
    if (hex.length() % 2 != 0) {
        log_msg("[UTIL] hex_to_bin error: Input hex '%s' has odd length.", hex.c_str());
        return false;
    }
    bin.clear();
    bin.reserve(hex.length() / 2);
    try {
        for (size_t i = 0; i < hex.length(); i += 2) {
            bin.push_back(static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
        }
    } catch (const std::invalid_argument& e) {
        log_msg("[UTIL] hex_to_bin error (invalid hex char?) converting '%s': %s", hex.c_str(), e.what()); return false;
    } catch (const std::out_of_range& e) {
         log_msg("[UTIL] hex_to_bin error (value out of range?) converting '%s': %s", hex.c_str(), e.what()); return false;
    } catch (...) {
        log_msg("[UTIL] hex_to_bin unknown error converting '%s'", hex.c_str()); return false;
    }
    return true;
}
// Hex string to C-style binary buffer conversion
bool hex_to_bin(const std::string& hex, unsigned char* bin_ptr, size_t bin_size) {
    if (!bin_ptr) return false;
    std::vector<unsigned char> temp_bin;
    if (!hex_to_bin(hex, temp_bin)) return false;
    if (temp_bin.size() != bin_size) {
        log_msg("[UTIL] hex_to_bin (ptr version) size mismatch (expected %zu, got %zu from hex '%s')", bin_size, temp_bin.size(), hex.c_str());
        return false;
    }
    memcpy(bin_ptr, temp_bin.data(), bin_size);
    return true;
}

// Convert uint32_t (Little Endian host format) to Big Endian hex string
std::string uint32_to_hex_be(uint32_t val_le) {
    uint32_t val_be = local_htobe32(val_le); // Convert LE host to BE network order
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << val_be;
    return ss.str();
}

// Increment Extranonce2 (Little Endian increment)
void increment_extranonce2(std::vector<unsigned char>& en2) {
    if (en2.empty()) return;
    // Increment from the least significant byte (index 0 for LE)
    for (size_t i = 0; i < en2.size(); ++i) {
        if (++en2[i] != 0) { // If incrementing doesn't cause a wrap-around (carry)
            return; // Done
        }
        // If en2[i] became 0, it means we wrapped around, so continue to increment the next byte (carry)
    }
    // If we exit the loop, it means all bytes wrapped around (e.g., 0xFF -> 0x00, 0xFFFF -> 0x0000)
    // This indicates the extranonce space for this size has been exhausted.
}

// --- Config Loading ---
bool load_config() {
    std::ifstream config_stream(CONFIG_FILE);
    if (!config_stream.is_open()) {
        fprintf(stderr, "%s[ERROR] Config file '%s' not found.%s\n", C_RED, CONFIG_FILE, C_RESET);
        // Create an example config file
        std::ofstream example_config(CONFIG_FILE);
        if (example_config) {
             example_config << "{\n";
             example_config << "  \"pool_host\": \"stratum.example.com\",\n";
             example_config << "  \"pool_port\": 3333,\n";
             example_config << "  \"wallet_address\": \"YOUR_BTC_WALLET_ADDRESS\",\n";
             example_config << "  \"threads\": 4,\n";
             example_config << "  \"pool_password\": \"x\",\n";
             example_config << "  \"log_file\": \"miner.log\"\n";
             example_config << "}\n";
             example_config.close();
             fprintf(stderr, "[INFO] Created example config file '%s'. Please edit it with your details.\n", CONFIG_FILE);
        } else {
             fprintf(stderr, "[ERROR] Could not create example config file '%s'.\n", CONFIG_FILE);
        }
        return false;
    }

    std::string config_content((std::istreambuf_iterator<char>(config_stream)), std::istreambuf_iterator<char>());
    config_stream.close();

    if (config_content.empty()) {
        fprintf(stderr, "%s[ERROR] Config file '%s' is empty.%s\n", C_RED, CONFIG_FILE, C_RESET);
        return false;
    }

    json_object *parsed_json = json_tokener_parse(config_content.c_str());
    if (!parsed_json) {
        fprintf(stderr, "%s[ERROR] Failed to parse JSON from config file '%s'. Check syntax.%s\n", C_RED, CONFIG_FILE, C_RESET);
        return false;
    }

    json_object *jval;
    bool success = true;
    std::string error_field = "";

    // Pool Host (required, string, not empty)
    if (success && json_object_object_get_ex(parsed_json, "pool_host", &jval) && json_object_is_type(jval, json_type_string)) {
        g_pool_host = json_object_get_string(jval);
        if (g_pool_host.empty()) { success = false; error_field = "pool_host (cannot be empty)"; }
    } else if (success) { success = false; error_field = "pool_host (must be a string)"; }

    // Pool Port (required, integer, 1-65535)
    if (success && json_object_object_get_ex(parsed_json, "pool_port", &jval) && json_object_is_type(jval, json_type_int)) {
        g_pool_port = json_object_get_int(jval);
        if (g_pool_port <= 0 || g_pool_port > 65535) { success = false; error_field = "pool_port (must be between 1 and 65535)"; }
    } else if (success) { success = false; error_field = "pool_port (must be an integer)"; }

    // Wallet Address (required, string, not empty, not default)
    if (success && json_object_object_get_ex(parsed_json, "wallet_address", &jval) && json_object_is_type(jval, json_type_string)) {
        g_wallet_addr = json_object_get_string(jval);
        if (g_wallet_addr.empty() || g_wallet_addr == "YOUR_BTC_WALLET_ADDRESS") { success = false; error_field = "wallet_address (cannot be empty or default example)"; }
    } else if (success) { success = false; error_field = "wallet_address (must be a string)"; }

    // Threads (required, integer, > 0)
    if (success && json_object_object_get_ex(parsed_json, "threads", &jval) && json_object_is_type(jval, json_type_int)) {
        int tc = json_object_get_int(jval);
        if (tc > 0) {
            g_threads = tc;
        } else { success = false; error_field = "threads (must be greater than 0)"; }
    } else if (success) { success = false; error_field = "threads (must be an integer)"; }

    // Pool Password (optional, string, defaults to "x")
    if (success && json_object_object_get_ex(parsed_json, "pool_password", &jval)) {
        if (json_object_is_type(jval, json_type_string)) {
            g_pool_password = json_object_get_string(jval); // Can be empty if desired
        } else { success = false; error_field = "pool_password (must be a string if provided)"; }
    }
    // If not provided, g_pool_password retains its default "x"

    // Log File (optional, string, defaults to "miner.log")
    if (success && json_object_object_get_ex(parsed_json, "log_file", &jval)) {
        if (json_object_is_type(jval, json_type_string)) {
            const char* logfile_str = json_object_get_string(jval);
            if (logfile_str && strlen(logfile_str) > 0) {
                g_log_file = logfile_str;
            } // If empty string provided, keep default
        } else { success = false; error_field = "log_file (must be a string if provided)"; }
    }
    // If not provided, g_log_file retains its default "miner.log"

    json_object_put(parsed_json); // Free the parsed json object

    if (!success) {
        fprintf(stderr, "%s[ERROR] Invalid or missing configuration in '%s': Check field '%s'.%s\n", C_RED, CONFIG_FILE, error_field.c_str(), C_RESET);
    } else {
        fprintf(stdout, "[CONFIG] Configuration successfully loaded and validated from %s\n", CONFIG_FILE);
    }
    return success;
}

// --- Signal Handler ---
void handle_sigint(int sig) {
    (void)sig; // Unused parameter
    // Use exchange to ensure shutdown actions happen only once
    if (g_sigint_shutdown.exchange(true)) {
        return; // Already shutting down
    }
    log_msg("[SIGNAL] SIGINT received, initiating shutdown...");
    fprintf(stderr, "\r%*s\r%s[SIGNAL] Shutdown initiated by SIGINT...%s\n", 80, "", C_YELLOW, C_RESET);
    fflush(stderr);
    // Signal connection loss to break loops and wake up threads
    g_connection_lost.store(true);
    g_new_job_cv.notify_all(); // Wake up any waiting threads
}

// --- Networking & Pool Communication ---

// Curl write callback
static size_t write_callback_cpp(void *ptr, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    std::string* mem = static_cast<std::string*>(userp);
    try {
        mem->append(static_cast<char*>(ptr), realsize);
    } catch (const std::bad_alloc& e) {
        fprintf(stderr, "%s[ERROR] Curl callback memory allocation failed: %s%s\n", C_RED, e.what(), C_RESET);
        return 0; // Signal error to curl
    } catch (...) {
        fprintf(stderr, "%s[ERROR] Curl callback unknown memory allocation error.%s\n", C_RED, C_RESET);
        return 0; // Signal error to curl
    }
    return realsize;
}

// Get current block height from an external API (e.g., mempool.space)
long get_current_block_height() {
    CURL *curl = curl_easy_init();
    if (!curl) {
        log_msg("[ERROR][HTTP] curl_easy_init failed.");
        return -1;
    }
    std::string chunk;
    long height = -1;
    // Using mempool.space API as an example
    const char* url = "https://mempool.space/api/blocks/tip/height";

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_cpp);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L); // 10 second timeout
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SimpleCppMiner/1.2-gmp"); // Set user agent
    // Disable SSL verification for simplicity IF NEEDED (not recommended for production)
    // curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    // curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 200) {
            try {
                height = std::stoll(chunk); // Use stoll for long
            } catch (const std::invalid_argument& e) {
                 log_msg("[ERROR][HTTP] Failed to parse height response '%s': %s", chunk.c_str(), e.what()); height = -1;
            } catch (const std::out_of_range& e) {
                 log_msg("[ERROR][HTTP] Height response '%s' out of range: %s", chunk.c_str(), e.what()); height = -1;
            } catch (...) {
                 log_msg("[ERROR][HTTP] Unknown error parsing height response '%s'", chunk.c_str()); height = -1;
            }
        } else {
             log_msg("[ERROR][HTTP] Failed to get height, HTTP status code: %ld, Response: %s", http_code, chunk.substr(0, 200).c_str());
             height = -1;
        }
    } else {
         log_msg("[ERROR][HTTP] curl_easy_perform() failed for height check: %s", curl_easy_strerror(res));
         height = -1;
    }

    curl_easy_cleanup(curl);
    return height;
}

// Connect to the mining pool
SOCKET connect_pool() {
    SOCKET sock = INVALID_SOCKET;
    struct addrinfo hints = {}, *servinfo = nullptr, *p = nullptr;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(g_pool_port);

    log_msg("[NET] Resolving %s:%d...", g_pool_host.c_str(), g_pool_port);
    if ((rv = getaddrinfo(g_pool_host.c_str(), port_str.c_str(), &hints, &servinfo)) != 0) {
        log_msg("[ERROR][NET] getaddrinfo failed for %s: %s", g_pool_host.c_str(), gai_strerror(rv));
        return INVALID_SOCKET;
    }

    // Loop through results and connect to the first we can
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        // Create socket
        if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == INVALID_SOCKET) {
            #ifdef _WIN32
                log_msg("[WARN][NET] socket() failed: %d", WSAGetLastError());
            #else
                log_msg("[WARN][NET] socket() failed: %s", strerror(errno));
            #endif
            continue;
        }

        // Get address string for logging
        char addr_str[INET6_ADDRSTRLEN];
        void *addr;
        if (p->ai_family == AF_INET) { // IPv4
             struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
             addr = &(ipv4->sin_addr);
        } else { // IPv6
             struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
             addr = &(ipv6->sin6_addr);
        }
        inet_ntop(p->ai_family, addr, addr_str, sizeof(addr_str));


        log_msg("[NET] Attempting connect to %s (%s) port %d...", g_pool_host.c_str(), addr_str, g_pool_port);

        // Connect
        if (connect(sock, p->ai_addr, p->ai_addrlen) == SOCKET_ERROR) {
            #ifdef _WIN32
                log_msg("[WARN][NET] connect() failed: %d", WSAGetLastError());
            #else
                log_msg("[WARN][NET] connect() failed: %s", strerror(errno));
            #endif
            closesocket(sock);
            sock = INVALID_SOCKET;
            continue;
        }

        // If connect was successful, break the loop
        log_msg("[NET] Successfully connected to %s:%d via %s", g_pool_host.c_str(), g_pool_port, addr_str);
        break;
    }

    freeaddrinfo(servinfo); // Free the linked list

    if (p == nullptr) {
        log_msg("[ERROR][NET] Failed to connect to any resolved address for %s:%d", g_pool_host.c_str(), g_pool_port);
        return INVALID_SOCKET;
    }

    log_msg("[NET] Connection established (FD/Socket: %d)", (int)sock);
    return sock;
}

// Send JSON string over socket (handles partial sends)
bool send_json(SOCKET sd, const std::string& json_str) {
    if (sd == INVALID_SOCKET) {
        log_msg("[ERROR][NET] send_json attempted on invalid socket.");
        return false;
    }
    std::string msg = json_str + "\n"; // Stratum messages usually end with newline
    ssize_t total_sent = 0;
    ssize_t remaining = msg.length();
    const char* ptr = msg.c_str();

    while (remaining > 0) {
        ssize_t bytes_sent;
#ifdef _WIN32
        bytes_sent = send(sd, ptr + total_sent, static_cast<int>(remaining), 0);
#else
        // Use MSG_NOSIGNAL on Linux/POSIX to prevent SIGPIPE if connection is broken
        bytes_sent = send(sd, ptr + total_sent, remaining, MSG_NOSIGNAL);
#endif

        if (bytes_sent == SOCKET_ERROR) {
#ifdef _WIN32
            int err = WSAGetLastError();
            // Retry on interrupt if not shutting down
            if (err == WSAEINTR && !g_sigint_shutdown.load()) continue;
            log_msg("[ERROR][NET] send() failed on socket %d: %d", (int)sd, err);
#else
            // Retry on interrupt if not shutting down
            if (errno == EINTR && !g_sigint_shutdown.load()) continue;
            log_msg("[ERROR][NET] send() failed on socket %d: %s", (int)sd, strerror(errno));
#endif
            // Send failure usually means connection is lost
            g_connection_lost.store(true);
            g_new_job_cv.notify_all();
            return false;
        }

        if (bytes_sent == 0) {
             // This shouldn't typically happen with blocking sockets unless connection closed
             log_msg("[WARN][NET] send() returned 0 on socket %d. Connection likely closing.", (int)sd);
             g_connection_lost.store(true);
             g_new_job_cv.notify_all();
             return false;
        }

        total_sent += bytes_sent;
        remaining -= bytes_sent;
    }
    // log_msg("[DEBUG][NET] Sent: %s", json_str.c_str()); // Optional debug log
    return true;
}

// --- Miner Logic Optimization Helpers ---

// Prepare input for the first SHA256 round (takes 80-byte header, outputs 128-byte padded block)
// Input h: 80-byte header template (LE) - first 76 bytes are fixed, last 4 are nonce (LE)
// Input n: nonce (LE format)
// Output ob: 128-byte buffer for sha256 function (padded data)
// Output ow: 32 * 32-bit words (Big Endian) for SSE input (derived from ob)
inline void prepare_first_round_input( const unsigned char h[80], uint32_t n_le, unsigned char ob[128], uint32_t ow[32]) {
    // Copy header template (first 76 bytes)
    memcpy(ob, h, 76);
    // Copy nonce (LE) into the last 4 bytes
    memcpy(ob + 76, &n_le, 4);

    // Padding: append 0x80, then zeros, then 64-bit length (640 bits = 80 bytes * 8)
    ob[80] = 0x80;
    memset(&ob[81], 0, 39); // Zero padding (128 - 80 - 1 - 8 = 39 bytes)
    uint64_t bit_length_be = local_htobe64(640); // 80 bytes * 8 bits/byte
    memcpy(&ob[120], &bit_length_be, 8); // Append length in Big Endian

    // Convert the 128-byte LE buffer (ob) to 32 BE words (ow) for SSE
    // Note: sha256sse expects input words in Big Endian format.
    // Our header (h) and nonce (n_le) are Little Endian. The sha256 padding is standard.
    // The conversion needs careful byte swapping. Let's reinterpret cast and swap.
    const uint32_t* pi = reinterpret_cast<const uint32_t*>(ob);
    for(int i=0; i < 32; ++i) { // Process 32 * 4 = 128 bytes
        ow[i] = local_htobe32(pi[i]); // Read LE 32-bit word, convert to BE 32-bit word
    }
    // Correction: SSE needs 16 words for the first block, not 32.
    // The above loop processes 128 bytes into 32 BE words. sha256sse_2B likely uses the first 16 for state init. Let's stick to this for now based on original code.
    // If sha256sse_2B expects only 16 words, the loop should be i < 16. BUT the padding extends to 128 bytes. Re-check sha256sse.cpp if needed.
    // Assuming the original logic preparing 32 words was correct for how sha256sse_2B is structured.
}


// Prepare input for the second SHA256 round (takes 32-byte hash, outputs 64-byte padded block -> 16 BE words)
// Input h: 32-byte hash result from the first round (BE)
// Output ow: 16 * 32-bit words (Big Endian) for SSE input
inline void prepare_second_round_input( const unsigned char h_be[32], uint32_t ow[16]) {
    alignas(16) unsigned char b[64]; // 64-byte buffer for padding
    // Copy the 32-byte BE hash
    memcpy(b, h_be, 32);

    // Padding: append 0x80, then zeros, then 64-bit length (256 bits = 32 bytes * 8)
    b[32] = 0x80;
    memset(&b[33], 0, 23); // Zero padding (64 - 32 - 1 - 8 = 23 bytes)
    uint64_t bit_length_be = local_htobe64(256); // 32 bytes * 8 bits/byte
    memcpy(&b[56], &bit_length_be, 8); // Append length in Big Endian

    // Convert the 64-byte padded buffer (b) to 16 BE words (ow) for SSE
    const uint32_t* pi = reinterpret_cast<const uint32_t*>(b);
    for(int i=0; i < 16; ++i) { // Process 16 * 4 = 64 bytes
        ow[i] = local_htobe32(pi[i]); // Read LE 32-bit word (from buffer b), convert to BE 32-bit word
        // Note: The input h_be was Big Endian. memcpy treats it as bytes.
        // The reinterpretation pi treats buffer 'b' as LE words on typical machines.
        // So, pi[i] reads a 32-bit chunk from 'b' assuming LE, then local_htobe32 swaps it to BE for SSE. This seems correct.
    }
}


// --- Miner Thread (Using GMP Target) ---
void miner_func(int thread_id, int num_threads) {
    log_msg("[MINER %d] Thread started.", thread_id);
    mpz_t local_share_target; // GMP target specific to this thread's current job batch
    mpz_init(local_share_target);
    bool share_target_loaded = false; // Track if local_share_target holds a valid value

    try { // Main try block for the thread function
        // Allocate SSE buffers (aligned for performance)
        alignas(16) uint32_t sse_input0[32], sse_input1[32], sse_input2[32], sse_input3[32]; // Input words (BE)
        alignas(16) unsigned char sse_digest_be0[32], sse_digest_be1[32], sse_digest_be2[32], sse_digest_be3[32]; // Output digests (BE)
        alignas(16) unsigned char pad_buffer0[128], pad_buffer1[128], pad_buffer2[128], pad_buffer3[128]; // Padding buffers

        // Thread-local state variables
        std::string current_job_id_local = "";       // Job ID this thread is currently working on
        size_t extranonce2_size_local = 4;         // Extranonce2 size for the current job
        std::vector<unsigned char> extranonce2_bin_local; // Current extranonce2 value for this thread

        // --- Main Mining Loop ---
        while (!g_sigint_shutdown.load()) {
            bool need_new_job = false;   // Flag: do we need to copy new job data?
            bool clean_job_flag = false; // Flag: was the new job marked as 'clean'?

            // --- Declare local job variables needed for hashing ---
            // --- Declared here so they are in scope for the hashing loop if need_new_job is true ---
            uint32_t version_local_le;
            std::vector<unsigned char> prevhash_local_bin_le;
            std::vector<unsigned char> coinb1_local_bin;
            std::vector<unsigned char> coinb2_local_bin;
            std::vector<unsigned char> extranonce1_local_bin;
            std::vector<std::vector<unsigned char>> merkle_branch_local_bin_be;
            uint32_t ntime_local_le;
            uint32_t nbits_local_le;
            // extranonce2_size_local and extranonce2_bin_local are already declared at a higher scope


            // --- Wait for a new job or shutdown ---
            {
                std::unique_lock<std::mutex> lock(g_job_mutex);

                // Wait until: shutdown OR connection lost OR (new job available AND its ID is different from ours)
                g_new_job_cv.wait(lock, [&]{
                    return g_sigint_shutdown.load() || g_connection_lost.load() || (g_new_job_available && g_job_id != current_job_id_local);
                });

                // --- Check conditions after waking up ---
                if (g_sigint_shutdown.load() || g_connection_lost.load()) {
                    break; // Exit the main while loop immediately
                }

                // Re-verify condition AFTER acquiring lock and waking up
                if (g_new_job_available && g_job_id != current_job_id_local) {

                    // Check for the rare race condition where the job ID changed back
                    if (g_job_id == current_job_id_local) {
                        log_msg("[MINER %d] Job %s is same as current after wait. Race condition? Re-waiting.", thread_id, g_job_id.c_str());
                        need_new_job = false;
                        // continue; // Let it fall through to the sleep at the end
                    } else {
                        // --- Passed checks, it's a genuinely new job we should process ---
                        need_new_job = true; // Assume we'll process it unless target loading fails
                        clean_job_flag = g_clean_jobs; // Get the clean flag associated with this job

                        // Copy necessary job details from global variables to local scope variables
                        version_local_le = g_version_le;
                        prevhash_local_bin_le = g_prevhash_bin; // Is already LE binary
                        coinb1_local_bin = g_coinb1_bin;
                        coinb2_local_bin = g_coinb2_bin;
                        extranonce1_local_bin = g_extranonce1_bin;
                        merkle_branch_local_bin_be = g_merkle_branch_bin_be; // Is BE binary
                        ntime_local_le = g_ntime_le;
                        nbits_local_le = g_nbits_le;       // Is LE host format
                        extranonce2_size_local = g_extranonce2_size; // Copy current size

                        // Copy the current global share target atomically
                        {
                            std::lock_guard<std::mutex> target_lock(g_share_target_mutex);
                            if (mpz_sgn(g_share_target) != 0) {
                                 mpz_set(local_share_target, g_share_target);
                                 share_target_loaded = true;
                            } else {
                                 share_target_loaded = false;
                                 log_msg("[WARN][MINER %d] Global share target is zero when trying to start job %s. Waiting for target.", thread_id, g_job_id.c_str());
                                 need_new_job = false; // Prevent processing this job iteration
                            }
                        }

                        // If target was loaded successfully, commit to this job:
                        // Update local job ID and initialize extranonce2
                        if (need_new_job) {
                            current_job_id_local = g_job_id; // <<< IMPORTANT: Update local ID *inside the lock*

                            // Initialize extranonce2 for the new job based on thread ID
                            extranonce2_bin_local.assign(extranonce2_size_local, 0);
                            if (!extranonce2_bin_local.empty() && num_threads > 0) {
                                uint64_t start_val = static_cast<uint64_t>(thread_id);
                                 for (size_t i = 0; i < extranonce2_bin_local.size() && i < sizeof(uint64_t); ++i) {
                                     extranonce2_bin_local[i] = static_cast<unsigned char>((start_val >> (i * 8)) & 0xFF);
                                 }
                            }
                            // Job details logging will happen outside the lock
                        }
                        // If need_new_job is false (target failed), we just release the lock and loop back to wait.
                    } // End else (job ID was different from current)
                } else {
                    // Spurious wakeup, or the job ID didn't actually change for us.
                    need_new_job = false; // Ensure we don't proceed
                }
            } // Mutex g_job_mutex lock is released here

            // --- Process New Job Data (only if need_new_job is true) ---
            if (need_new_job) {
                // Log job start details (now that we have committed and copied data)
                char* sth = nullptr;
                if (share_target_loaded) { sth = mpz_get_str(NULL, 16, local_share_target); }
                // Use the local variables that were just populated
                log_msg("[MINER %d] Starting job %s (Clean:%s E2Size:%zu E2Start(LE):%s NetNB:0x%08x ShareTgt:%s)",
                        thread_id, current_job_id_local.c_str(), clean_job_flag ? "Y" : "N",
                        extranonce2_size_local, bin_to_hex(extranonce2_bin_local).c_str(),
                        nbits_local_le, // Use nbits_local_le
                        (share_target_loaded && sth) ? sth : (share_target_loaded ? "Error" : "NotSet"));
                if(sth) free(sth);

                // --- Hashing Loop (iterates through extranonce2 values for this job) ---
                bool job_abandoned_by_thread = false; // Flag: Did this thread stop working on this job prematurely?
                while (!job_abandoned_by_thread && !g_sigint_shutdown.load() && !g_connection_lost.load()) {

                    // --- Periodically check for newer job / target update ---
                    {
                        std::unique_lock<std::mutex> lock(g_job_mutex, std::try_to_lock);
                        if (lock.owns_lock()) {
                            if (g_job_id != current_job_id_local) { // Check if global job ID changed
                                log_msg("[MINER %d] New job %s received while working on %s. Abandoning old job.", thread_id, g_job_id.c_str(), current_job_id_local.c_str());
                                job_abandoned_by_thread = true;
                            } else {
                                std::lock_guard<std::mutex> target_lock(g_share_target_mutex);
                                if (mpz_sgn(g_share_target) == 0) {
                                     log_msg("[WARN][MINER %d] Global share target became zero mid-job %s. Abandoning work.", thread_id, current_job_id_local.c_str());
                                     share_target_loaded = false; job_abandoned_by_thread = true;
                                } else if (share_target_loaded && mpz_cmp(g_share_target, local_share_target) != 0) {
                                     mpz_set(local_share_target, g_share_target); /* Optional log */
                                }
                            }
                        } // Release lock
                        if (job_abandoned_by_thread || !share_target_loaded) break; // Exit extranonce2 loop
                    }

                    // --- Calculate Merkle Root --- Use local variables ---
                    alignas(16) unsigned char current_merkle_root_le[32];
                    try {
                        // Pass the local copies of job data to the function
                        std::vector<unsigned char> merkle_root_vec = calculate_simplified_merkle_root_le(
                            coinb1_local_bin, extranonce1_local_bin, extranonce2_bin_local, // Use local versions
                            coinb2_local_bin, merkle_branch_local_bin_be);                  // Use local versions
                        if (merkle_root_vec.size() != 32) { /* Error handling */ job_abandoned_by_thread = true; continue; }
                        memcpy(current_merkle_root_le, merkle_root_vec.data(), 32);
                    } catch (const std::exception& e) { /* Error handling */ job_abandoned_by_thread = true; continue;
                    } catch (...) { /* Error handling */ job_abandoned_by_thread = true; continue; }

                    // --- Construct Block Header Template --- Use local variables ---
                    alignas(16) unsigned char header_template_le[80];
                    memcpy(header_template_le, &version_local_le, 4);           // Use local version
                    memcpy(header_template_le + 4, prevhash_local_bin_le.data(), 32); // Use local prevhash
                    memcpy(header_template_le + 36, current_merkle_root_le, 32);    // Use calculated merkle root
                    memcpy(header_template_le + 68, &ntime_local_le, 4);           // Use local nTime
                    memcpy(header_template_le + 72, &nbits_local_le, 4);           // Use local nBits

                    // --- Nonce Loop ---
                    uint32_t nonce_stride = static_cast<uint32_t>(num_threads) * 4;
                    if (nonce_stride == 0) nonce_stride = 4;
                    uint32_t n_start = static_cast<uint32_t>(thread_id) * 4;
                    bool nonce_wrap_detected = false;

                    for (uint32_t n_base = n_start; !nonce_wrap_detected; ) {
                        // --- Periodic checks ---
                        if ((n_base & 0xFFFF) == 0) {
                            if (g_sigint_shutdown.load() || g_connection_lost.load()) { job_abandoned_by_thread = true; break; }
                            { // Non-blocking check for new job/target
                                std::unique_lock<std::mutex> lock(g_job_mutex, std::try_to_lock);
                                if (lock.owns_lock()) {
                                    if (g_job_id != current_job_id_local) { job_abandoned_by_thread = true; }
                                    else { std::lock_guard<std::mutex> tl(g_share_target_mutex); if (mpz_sgn(g_share_target) == 0) { job_abandoned_by_thread = true; share_target_loaded = false; } else if (share_target_loaded && mpz_cmp(g_share_target, local_share_target) != 0) { mpz_set(local_share_target, g_share_target); } }
                                }
                            }
                            if (job_abandoned_by_thread || !share_target_loaded) break;
                        }

                        // --- Prepare SSE inputs --- (Uses header_template_le)
                        uint32_t nonce0_le = n_base + 0; uint32_t nonce1_le = n_base + 1; uint32_t nonce2_le = n_base + 2; uint32_t nonce3_le = n_base + 3;
                        prepare_first_round_input(header_template_le, nonce0_le, pad_buffer0, sse_input0);
                        prepare_first_round_input(header_template_le, nonce1_le, pad_buffer1, sse_input1);
                        prepare_first_round_input(header_template_le, nonce2_le, pad_buffer2, sse_input2);
                        prepare_first_round_input(header_template_le, nonce3_le, pad_buffer3, sse_input3);

                        // --- Double SHA256 (SSE) ---
                        sha256sse_2B(sse_input0, sse_input1, sse_input2, sse_input3, sse_digest_be0, sse_digest_be1, sse_digest_be2, sse_digest_be3);
                        prepare_second_round_input(sse_digest_be0, sse_input0); prepare_second_round_input(sse_digest_be1, sse_input1); prepare_second_round_input(sse_digest_be2, sse_input2); prepare_second_round_input(sse_digest_be3, sse_input3);
                        sha256sse_1B(sse_input0, sse_input1, sse_input2, sse_input3, sse_digest_be0, sse_digest_be1, sse_digest_be2, sse_digest_be3);

                        // --- Increment hash count ---
                        g_thread_hash_counts[thread_id].fetch_add(4, std::memory_order_relaxed);

                        // --- Check results against share target --- (Uses local_share_target)
                        const unsigned char* digests_be[] = {sse_digest_be0, sse_digest_be1, sse_digest_be2, sse_digest_be3};
                        uint32_t winning_nonce_le = 0; int winning_index = -1;
                        for (int i = 0; i < 4; ++i) {
                            unsigned char hash_le[32]; memcpy(hash_le, digests_be[i], 32); std::reverse(hash_le, hash_le + 32);
                            if (share_target_loaded && is_hash_less_or_equal_target_gmp(hash_le, local_share_target)) { // Use local_share_target
                                winning_nonce_le = n_base + i; winning_index = i; break;
                            }
                        }

                        // --- Handle Share Found ---
                        if (winning_index != -1) {
                            // ... (Share found logging and submission logic - uses ntime_local_le, nbits_local_le, current_job_id_local, extranonce2_bin_local) ...
                            const unsigned char* winning_digest_be = digests_be[winning_index];
                            std::string hash_hex_be = bin_to_hex(winning_digest_be, 32);
                            std::string share_timestamp = timestamp_us();
                            unsigned char winning_hash_le[32]; memcpy(winning_hash_le, winning_digest_be, 32); std::reverse(winning_hash_le, winning_hash_le + 32);
                            bool meets_network_target = is_hash_less_than_target(winning_hash_le, nbits_local_le); // Use nbits_local_le

                            fprintf(stderr, "\r%*s\r", 80, "");
                            fprintf(stdout, "%s[T%d %s] Share found! Job: %s Nonce: 0x%08x %s%s\n", C_GREEN, thread_id, share_timestamp.c_str(), current_job_id_local.c_str(), winning_nonce_le, meets_network_target ? "[BLOCK!]" : "", C_RESET); fflush(stdout);

                            char* sth_log = mpz_get_str(NULL, 16, local_share_target);
                            log_msg("[SHARE FOUND][T%d] Job=%s N(LE)=0x%08x H(BE)=%s Tgt=%s E2(LE)=%s %s", thread_id, current_job_id_local.c_str(), winning_nonce_le, hash_hex_be.c_str(), sth_log ? sth_log : "?", bin_to_hex(extranonce2_bin_local).c_str(), meets_network_target ? "[BLOCK!]" : "");
                            if(sth_log) free(sth_log);

                            std::string ntime_hex_be = uint32_to_hex_be(ntime_local_le); // Use ntime_local_le
                            std::string nonce_hex_be = uint32_to_hex_be(winning_nonce_le);
                            std::string extranonce2_hex = bin_to_hex(extranonce2_bin_local);
                            std::stringstream ss_payload; ss_payload.imbue(std::locale::classic());
                            long long submit_id = std::chrono::high_resolution_clock::now().time_since_epoch().count(); if (submit_id < 100) submit_id += 100;
                            ss_payload << R"({"id":)" << submit_id << R"(,"method":"mining.submit","params":[")" << g_wallet_addr << R"(",")" << current_job_id_local << R"(",")" << extranonce2_hex << R"(",")" << ntime_hex_be << R"(",")" << nonce_hex_be << R"("]})";

                            SOCKET sock_to_use = g_sockfd.load(std::memory_order_relaxed);
                            if (sock_to_use != INVALID_SOCKET) {
                                if (!send_json(sock_to_use, ss_payload.str())) { /* Log */ } else { /* Log */ }
                            } else { /* Log, signal loss */ g_connection_lost.store(true); g_new_job_cv.notify_all(); }

                            job_abandoned_by_thread = true; // Found share, stop working on this extranonce2
                            break; // Exit the nonce loop
                        }

                        // --- Check for Nonce Wrap-around ---
                        if (n_base > UINT32_MAX - nonce_stride) {
                             log_msg("[WARN][T%d] Nonce space exhausted for job %s, E2(LE): %s.", thread_id, current_job_id_local.c_str(), bin_to_hex(extranonce2_bin_local).c_str());
                             nonce_wrap_detected = true; // Signal to exit nonce loop
                        } else {
                            n_base += nonce_stride; // Increment base nonce
                        }
                    } // --- End of Nonce Loop ---

                    // If job was abandoned (share found, new job, shutdown, error), break extranonce2 loop
                    if (job_abandoned_by_thread) { break; }

                    // Increment Extranonce2 (Little Endian)
                    increment_extranonce2(extranonce2_bin_local);

                    // --- Check if Extranonce2 space wrapped around for this thread ---
                    bool e2_wrapped = false;
                    if (!extranonce2_bin_local.empty() && num_threads > 0) {
                         uint64_t current_e2_val = 0;
                         for (size_t i = 0; i < extranonce2_bin_local.size() && i < sizeof(uint64_t); ++i) { current_e2_val |= static_cast<uint64_t>(extranonce2_bin_local[i]) << (i * 8); }
                         uint64_t start_e2_val = static_cast<uint64_t>(thread_id);
                         if (current_e2_val == start_e2_val) { e2_wrapped = true; }
                    } else if (extranonce2_size_local == 0) { e2_wrapped = true; }

                    if (e2_wrapped && extranonce2_size_local > 0) {
                        log_msg("[WARN][T%d] Extranonce2 space potentially exhausted for job %s. Waiting for new job.", thread_id, current_job_id_local.c_str());
                        job_abandoned_by_thread = true; // Mark job as done, wait for next job notification
                    }
                    // If not wrapped, loop continues with next extranonce2 value

                } // --- End of Extranonce2 Loop ---
            } // --- End of if (need_new_job) ---
            else {
                // If we woke up but didn't process a job (spurious, target not ready, race condition)
                // Add a small sleep to prevent potential busy-waiting.
                if (!g_sigint_shutdown.load() && !g_connection_lost.load()) {
                     std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }
            }

        } // --- End of Main Mining Loop (while !g_sigint_shutdown.load()) ---

    } // End of try block
    catch (const std::exception& e) {
        log_msg("[FATAL][MINER %d] Terminating due to exception: %s", thread_id, e.what());
        g_connection_lost.store(true); g_new_job_cv.notify_all();
    } catch (...) {
        log_msg("[FATAL][MINER %d] Terminating due to unknown exception.", thread_id);
        g_connection_lost.store(true); g_new_job_cv.notify_all();
    }

    // --- Cleanup Actions before thread exits ---
    mpz_clear(local_share_target);
    if (!g_sigint_shutdown.load() && !g_connection_lost.load()) {
        log_msg("[MINER %d] Exiting unexpectedly, signaling connection lost.", thread_id);
        g_connection_lost.store(true); g_new_job_cv.notify_all();
    }
    log_msg("[MINER %d] Thread finished.", thread_id);
} // --- End of miner_func ---

void subscribe_func() {
    SOCKET sock = INVALID_SOCKET;
    std::string buffer_agg;
    log_msg("[SUB] Subscribe thread started.");

    try {
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Wait a bit for main thread to potentially connect

        while(!g_sigint_shutdown.load()) {
            sock = g_sockfd.load(std::memory_order_acquire);
            if(sock == INVALID_SOCKET) {
                // Socket not ready or already closed, wait and retry
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            log_msg("[SUB] Socket FD %d valid. Sending subscribe/authorize.", (int)sock);
            // Send subscribe
            if (!send_json(sock, R"({"id": 1, "method": "mining.subscribe", "params": ["SimpleCppMiner/1.2-gmp"]})")) {
                log_msg("[SUB] Send subscribe failed. Waiting for reconnect.");
                // Rely on main loop to handle reconnect based on g_connection_lost
                std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY_SECONDS));
                continue;
            }
            // Send authorize
            std::stringstream ss_auth;
            ss_auth.imbue(std::locale::classic());
            ss_auth << R"({"id":2,"method":"mining.authorize","params":[")" << g_wallet_addr << R"(",")" << g_pool_password << R"("]})";
            if (!send_json(sock, ss_auth.str())) {
                log_msg("[SUB] Send authorize failed. Waiting for reconnect.");
                 // Rely on main loop to handle reconnect based on g_connection_lost
                std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY_SECONDS));
                continue;
            }

            buffer_agg.clear(); // Clear any previous buffer data
            log_msg("[SUB] Waiting for pool messages on FD %d...", (int)sock);

            // Inner loop: Process messages while connected
            while (!g_sigint_shutdown.load() && g_sockfd.load(std::memory_order_relaxed) == sock) {
                 fd_set read_fds;
                 FD_ZERO(&read_fds);
                 // Re-check sock validity inside the loop before using it
                 SOCKET current_sock_check = g_sockfd.load(std::memory_order_relaxed); // Use atomic load
                 if (current_sock_check == INVALID_SOCKET || current_sock_check != sock) break; // Exit if socket changed or invalid
                 FD_SET(sock, &read_fds);

                 struct timeval timeout;
                 timeout.tv_sec = 2; // Timeout for select
                 timeout.tv_usec = 0;
                 // No need to check sock again here, select will handle EBADF if closed between check and select

                 int activity = select(sock + 1, &read_fds, NULL, NULL, &timeout);

                 // Handle select errors
                 if (activity < 0) {
#ifdef _WIN32
                    int err = WSAGetLastError();
                    // Break on genuine errors or shutdown signal during EINTR
                    if ((err == WSAEINTR && g_sigint_shutdown.load()) || err == WSAENOTSOCK || err == WSAECONNRESET || err == WSAECONNABORTED) break; // Break on critical errors
                    // Log other errors but continue if it's just EINTR without shutdown
                    if(err != WSAEINTR) {
                        log_msg("[ERR][SUB] select() failed: %d. Throwing.", err);
                        throw std::runtime_error("select error (Windows)");
                    }
#else
                    // Break on genuine errors or shutdown signal during EINTR
                    if ((errno == EINTR && g_sigint_shutdown.load()) || errno == EBADF || errno == ECONNRESET) break; // Break on critical errors
                    // Log other errors but continue if it's just EINTR without shutdown
                    if(errno != EINTR) {
                         log_msg("[ERR][SUB] select() failed: %s. Throwing.", strerror(errno));
                         throw std::runtime_error("select error (POSIX)");
                    }
#endif
                    // If we reach here, it was EINTR without shutdown, so continue loop
                    log_msg("[DEBUG][SUB] select() interrupted (EINTR), continuing.");
                    continue;
                 }

                 // Handle select timeout (no data)
                 if (activity == 0) continue;

                 // Data available, try to read
                 char buffer[8192];
                 ssize_t bytes_read;
#ifdef _WIN32
                 // Use the socket descriptor checked at the start of the loop
                 bytes_read = recv(sock, buffer, sizeof(buffer) - 1, 0);
#else
                 bytes_read = read(sock, buffer, sizeof(buffer) - 1);
#endif
                 // Handle read errors or disconnection
                 if (bytes_read <= 0) {
                     if (bytes_read == 0) {
                         log_msg("[SUB] Pool disconnected FD %d (read 0 bytes).", (int)sock);
                     } else { // bytes_read < 0 indicates an error
#ifdef _WIN32
                         int err = WSAGetLastError();
                         log_msg("[ERR][SUB] recv() FD %d failed: %d", (int)sock, err);
                         // Break immediately on critical socket errors (WSAENOTSOCK handled by select break)
                         if (err == WSAECONNABORTED || err == WSAECONNRESET) break;
#else
                         log_msg("[ERR][SUB] read() FD %d failed: %s", (int)sock, strerror(errno));
                         // Break immediately on critical socket errors (EBADF handled by select break)
                         if (errno == ECONNRESET) break;
#endif
                     }
                     // For any read error or graceful close, throw to trigger reconnect logic
                     throw std::runtime_error("Pool connection lost or read error during read/recv");
                 }

                 // Process received data
                 buffer[bytes_read] = '\0'; // Null-terminate the buffer
                 buffer_agg.append(buffer);

                 // Process line by line from aggregated buffer
                 size_t pos = 0;
                 std::string line;
                 while ((pos = buffer_agg.find('\n')) != std::string::npos) {
                    line = buffer_agg.substr(0, pos);
                    buffer_agg.erase(0, pos + 1); // Remove processed line + newline

                    if (line.empty() || line == "\r") continue; // Skip empty lines

                    // Parse JSON
                    json_object *parsed = json_tokener_parse(line.c_str());
                    if (!parsed) {
                        log_msg("[ERROR][SUB] JSON parse error for line: %s", line.c_str());
                        continue; // Skip this line, try next
                    }

                    // Extract common JSON fields
                    json_object *jmethod = nullptr, *jparams = nullptr, *jresult = nullptr, *jerror = nullptr, *jid = nullptr;
                    json_type jid_type = json_type_null;
                    long long msg_id_ll = -1; // Use long long for ID

                    if (json_object_object_get_ex(parsed, "id", &jid)) {
                        jid_type = json_object_get_type(jid);
                        if(jid_type == json_type_int) {
                            msg_id_ll = json_object_get_int64(jid);
                        } else if(jid_type == json_type_string) {
                            log_msg("[WARN][SUB] Received string ID from pool: %s", json_object_get_string(jid));
                        }
                    }
                    bool has_method = json_object_object_get_ex(parsed, "method", &jmethod) && json_object_is_type(jmethod, json_type_string);
                    bool has_result = json_object_object_get_ex(parsed, "result", &jresult);
                    bool has_error = json_object_object_get_ex(parsed, "error", &jerror) && !json_object_is_type(jerror, json_type_null);

                    // Process based on message type (Response vs Notification)
                    try { // Inner try-catch for processing a single message
                        if (jid_type == json_type_int && msg_id_ll >= 0) { // It's a Response
                            if (has_error) { // Error Response
                                const char* err_str = json_object_to_json_string_ext(jerror, JSON_C_TO_STRING_PLAIN);
                                log_msg("[ERR][SUB] Pool error response ID %lld: %s", msg_id_ll, err_str ? err_str : "N/A");
                                fprintf(stderr, "\r%*s\r%s[%s] Pool Error (ID %lld): %s%s\n", 80, "", C_RED, timestamp_us().c_str(), msg_id_ll, err_str ? err_str : "?", C_RESET); fflush(stderr);
                                // Specific handling for critical errors
                                if (msg_id_ll == 1) { // Subscribe failed
                                    throw std::runtime_error("Subscribe failed via pool error response");
                                } else if (msg_id_ll == 2) { // Authorize failed
                                     fprintf(stderr, "\r%*s\r%s[%s] AUTH FAILED: %s%s\n", 80, "", C_RED, timestamp_us().c_str(), err_str ? err_str : "?", C_RESET); fflush(stderr);
                                     throw std::runtime_error("Authorization failed via pool error response");
                                } else if (msg_id_ll >= 100) { // Share submission rejected
                                     fprintf(stderr, "\r%*s\r%s[%s] Share REJECTED (ID %lld): %s%s\n", 80, "", C_RED, timestamp_us().c_str(), msg_id_ll, err_str ? err_str : "?", C_RESET); fflush(stderr);
                                     // Continue mining
                                }
                            } else if (has_result) { // Success Response (or result is null)
                                if (msg_id_ll == 1) { // Subscribe Response
                                    if (json_object_is_type(jresult, json_type_array) && json_object_array_length(jresult) >= 3) {
                                        json_object* j_e1 = json_object_array_get_idx(jresult, 1);
                                        json_object* j_e2s = json_object_array_get_idx(jresult, 2);
                                        if (j_e1 && json_object_is_type(j_e1, json_type_string) &&
                                            j_e2s && json_object_is_type(j_e2s, json_type_int)) {
                                            const char* e1h = json_object_get_string(j_e1);
                                            int e2s_i = json_object_get_int(j_e2s);
                                            // Lock job mutex to update global extranonce info safely
                                            std::lock_guard<std::mutex> lock(g_job_mutex);
                                            if (hex_to_bin(e1h, g_extranonce1_bin)) {
                                                g_extranonce2_size = static_cast<size_t>(e2s_i);
                                                log_msg("[SUB] Subscribe OK. E1: %s (%zuB), E2Size: %zu", e1h, g_extranonce1_bin.size(), g_extranonce2_size);
                                                fprintf(stdout, "[POOL] Subscribe OK. Extranonce2 Size: %zu\n", g_extranonce2_size); fflush(stdout);
                                            } else {
                                                log_msg("[ERR][SUB] Failed to convert extranonce1 hex '%s'", e1h ? e1h : "N/A");
                                                throw std::runtime_error("Failed to parse extranonce1 from subscribe response");
                                            }
                                        } else { throw std::runtime_error("Invalid subscribe response format (param types)"); }
                                    } else { throw std::runtime_error("Invalid subscribe response format (structure)"); }
                                } else if (msg_id_ll == 2) { // Authorize Response
                                    bool auth_ok = false;
                                    if (json_object_is_type(jresult, json_type_boolean)) auth_ok = json_object_get_boolean(jresult);
                                    else if (json_object_is_type(jresult, json_type_null)) { auth_ok = true; log_msg("[WARN][SUB] Authorize result was null, treating as OK."); }
                                    else { log_msg("[WARN][SUB] Unexpected authorize result type: %s", json_type_to_name(json_object_get_type(jresult))); auth_ok = false; } // Treat unexpected as failure
                                    log_msg("[SUB] Authorization %s.", auth_ok ? "successful" : "failed");
                                    if (auth_ok) { fprintf(stdout, "%s[POOL] Authorization OK.%s\n", C_GREEN, C_RESET); fflush(stdout); }
                                    else { fprintf(stderr, "\r%*s\r%s[%s] AUTHORIZATION FAILED! Check wallet/password.%s\n", 80, "", C_RED, timestamp_us().c_str(), C_RESET); fflush(stderr); throw std::runtime_error("Authorization failed"); }
                                } else if (msg_id_ll >= 100) { // Share Submit Response
                                    bool share_accepted = false;
                                    if(json_object_is_type(jresult, json_type_boolean)) share_accepted = json_object_get_boolean(jresult);
                                    else if (json_object_is_type(jresult, json_type_null)) share_accepted = true;
                                    if (share_accepted) { log_msg("[SUB] Share (ID %lld) accepted by pool.", msg_id_ll); fprintf(stdout, "%s[%s] Share Accepted! (ID %lld)%s\n", C_GREEN, timestamp_us().c_str(), msg_id_ll, C_RESET); fflush(stdout); }
                                    else { const char* res_str = json_object_to_json_string_ext(jresult, JSON_C_TO_STRING_PLAIN); log_msg("[WARN][SUB] Share (ID %lld) potentially rejected by pool. Result: %s", msg_id_ll, res_str ? res_str : "N/A"); fprintf(stderr, "\r%*s\r%s[%s] Share Rejected? (ID %lld) Result: %s%s\n", 80, "", C_YELLOW, timestamp_us().c_str(), msg_id_ll, res_str ? res_str : "N/A", C_RESET); fflush(stderr); }
                                } else { log_msg("[WARN][SUB] Received success result for unexpected ID: %lld", msg_id_ll); }
                            } else { log_msg("[WARN][SUB] Response received for ID %lld with no 'result' and no 'error' field.", msg_id_ll); }
                        }
                        else if (has_method) { // It's a Notification
                            const char* method_name = json_object_get_string(jmethod);

                            if (strcmp(method_name, "mining.notify") == 0) {
                                // --- Handle mining.notify ---
                                if (json_object_object_get_ex(parsed,"params",&jparams) && json_object_is_type(jparams,json_type_array) && json_object_array_length(jparams)>=9) {
                                    json_object *j_jid=json_object_array_get_idx(jparams,0), *j_ph=json_object_array_get_idx(jparams,1), *j_cb1=json_object_array_get_idx(jparams,2), *j_cb2=json_object_array_get_idx(jparams,3), *j_mb=json_object_array_get_idx(jparams,4), *j_v=json_object_array_get_idx(jparams,5), *j_nb=json_object_array_get_idx(jparams,6), *j_nt=json_object_array_get_idx(jparams,7), *j_cj=json_object_array_get_idx(jparams,8);
                                    if(!j_jid || !json_object_is_type(j_jid,json_type_string)||!j_ph || !json_object_is_type(j_ph,json_type_string)||!j_cb1|| !json_object_is_type(j_cb1,json_type_string)||!j_cb2|| !json_object_is_type(j_cb2,json_type_string)||!j_mb || !json_object_is_type(j_mb,json_type_array) ||!j_v  || !json_object_is_type(j_v,json_type_string)||!j_nb || !json_object_is_type(j_nb,json_type_string)||!j_nt || !json_object_is_type(j_nt,json_type_string)||!j_cj || !json_object_is_type(j_cj,json_type_boolean)){ log_msg("[ERR][SUB] mining.notify message has incorrect parameter types. Line: %s", line.c_str()); }
                                    else {
                                        const char* job_id_str = json_object_get_string(j_jid); const char* ph_h = json_object_get_string(j_ph); const char* cb1_h = json_object_get_string(j_cb1); const char* cb2_h = json_object_get_string(j_cb2); const char* v_h = json_object_get_string(j_v); const char* nb_h = json_object_get_string(j_nb); const char* nt_h = json_object_get_string(j_nt); bool clean_j = json_object_get_boolean(j_cj);
                                        std::lock_guard<std::mutex> lock(g_job_mutex); bool conversion_ok = true;
                                        std::vector<unsigned char> tph; if(!hex_to_bin(ph_h,tph)||tph.size()!=32){log_msg("[ERR][SUB] Bad prevhash '%s'",ph_h);conversion_ok=false;}else{std::reverse(tph.begin(),tph.end());g_prevhash_bin=std::move(tph);}
                                        if(conversion_ok&&!hex_to_bin(cb1_h,g_coinb1_bin)){log_msg("[ERR][SUB] Bad coinb1 '%s'",cb1_h);conversion_ok=false;}
                                        if(conversion_ok&&!hex_to_bin(cb2_h,g_coinb2_bin)){log_msg("[ERR][SUB] Bad coinb2 '%s'",cb2_h);conversion_ok=false;}
                                        if(conversion_ok){g_merkle_branch_bin_be.clear(); size_t bl=json_object_array_length(j_mb);g_merkle_branch_bin_be.reserve(bl); for(size_t i=0;i<bl;++i){json_object* jbh=json_object_array_get_idx(j_mb,i);if(!jbh||!json_object_is_type(jbh,json_type_string)){log_msg("[ERR][SUB] Bad merkle type idx %zu",i);conversion_ok=false;break;} const char* bh=json_object_get_string(jbh);std::vector<unsigned char> bb;if(!hex_to_bin(bh,bb)||bb.size()!=32){log_msg("[ERR][SUB] Bad merkle hex '%s' idx %zu",bh?bh:"?",i);conversion_ok=false;break;} g_merkle_branch_bin_be.push_back(std::move(bb));}}
                                        uint32_t t_v=0, t_nb=0, t_nt=0; if(conversion_ok){try{t_v=local_be32toh(static_cast<uint32_t>(std::stoul(v_h,nullptr,16))); t_nb=local_be32toh(static_cast<uint32_t>(std::stoul(nb_h,nullptr,16))); t_nt=local_be32toh(static_cast<uint32_t>(std::stoul(nt_h,nullptr,16))); g_version_le=t_v; g_nbits_le=t_nb; g_ntime_le=t_nt;}catch(...){log_msg("[ERR][SUB] Bad V/NB/NT hex conversion");conversion_ok=false;}}
                                        if(conversion_ok){static std::string lphn="";bool new_blk=(std::string(ph_h)!=lphn);if(new_blk){lphn=ph_h;long ch=g_current_height.load();if(ch>0){g_current_height++;ch++;}double nd=calculate_difficulty(g_nbits_le);log_msg("[JOB] New Block ~%ld. Job: %s (Clean:%s Diff:%.3f nBits:0x%08x)",ch>0?ch:0,job_id_str,clean_j?"Y":"N",nd,g_nbits_le);fprintf(stdout,"\r%*s\r%s[*] New Block ~%ld | NetDiff: %.3e | Job: %s%s\n",80,"",C_YELLOW,ch>0?ch:0,nd,job_id_str,C_RESET);fflush(stdout);}else{log_msg("[JOB] New Job: %s (Clean:%s)",job_id_str,clean_j?"Y":"N");} g_job_id=job_id_str; g_clean_jobs=clean_j; g_new_job_available=true; g_new_job_cv.notify_all();}
                                        else{log_msg("[ERR][SUB] Job %s discarded due to conversion errors",job_id_str?job_id_str:"???");}
                                    }
                                } else { log_msg("[ERR][SUB] Bad notify params structure. Line: %s", line.c_str()); }
                            }
                            // --- Corrected GMP Difficulty Setting ---
                            else if (strcmp(method_name, "mining.set_difficulty") == 0) {
                                if (json_object_object_get_ex(parsed, "params", &jparams) && json_object_is_type(jparams, json_type_array) && json_object_array_length(jparams) > 0) {
                                    json_object* jdiff = json_object_array_get_idx(jparams, 0);
                                    if (jdiff) {
                                         json_type diff_type = json_object_get_type(jdiff); double pool_difficulty = 0.0; bool difficulty_ok = false;
                                         if (diff_type == json_type_double) { pool_difficulty = json_object_get_double(jdiff); difficulty_ok = true; log_msg("[SUB] Received pool difficulty (double): %.5f", pool_difficulty); fprintf(stdout, "[POOL] Difficulty set to: %.5f\n", pool_difficulty); fflush(stdout); }
                                         else if (diff_type == json_type_int) { pool_difficulty = static_cast<double>(json_object_get_int64(jdiff)); difficulty_ok = true; log_msg("[SUB] Received pool difficulty (int): %lld", (long long)pool_difficulty); fprintf(stdout, "[POOL] Difficulty set to: %lld\n", (long long)pool_difficulty); fflush(stdout); }
                                         else { const char* diff_str = json_object_to_json_string(jdiff); log_msg("[WARN][SUB] Difficulty has unexpected type (%s): %s. Ignoring.", json_type_to_name(diff_type), diff_str ? diff_str : "?"); fprintf(stdout, "[POOL] Difficulty has type %s: %s (Ignored)\n", json_type_to_name(diff_type), diff_str ? diff_str : "?"); fflush(stdout); difficulty_ok = false; }

                                        // ======== CORRECTED TARGET CALCULATION START ========
                                        if (difficulty_ok && pool_difficulty > 0.0) {
                                            mpz_t network_target, target1, temp_target; mpz_inits(network_target, target1, temp_target, NULL);
                                            try {
                                                uint32_t nbits_le_local;
                                                { std::lock_guard<std::mutex> lock(g_job_mutex); nbits_le_local = g_nbits_le; }
                                                if (nbits_le_local == 0) { log_msg("[WARN][SUB] nBits is 0, cannot calculate network target. Skipping difficulty update."); mpz_clears(network_target, target1, temp_target, NULL); }
                                                else {
                                                    uint32_t nbits_be = local_htobe32(nbits_le_local); uint32_t exponent = (nbits_be >> 24) & 0xFF; uint32_t coefficient = nbits_be & 0x00FFFFFF;
                                                    if (coefficient == 0 || exponent < 3 || exponent > 32) { log_msg("[WARN][SUB] Current job has invalid nBits (coeff=%u, exp=%u). Skipping difficulty update.", coefficient, exponent); mpz_clears(network_target, target1, temp_target, NULL); }
                                                    else {
                                                        mpz_set_ui(network_target, coefficient); mpz_mul_2exp(network_target, network_target, 8 * (static_cast<int>(exponent) - 3));
                                                        mpz_t calculated_share_target; mpz_init(calculated_share_target);
                                                        if (diff_type == json_type_int) { long long pd_int = json_object_get_int64(jdiff); if (pd_int > 0) { mpz_tdiv_q_ui(calculated_share_target, network_target, (unsigned long)pd_int); } else { mpz_set(calculated_share_target, network_target); log_msg("[WARN][SUB] Pool difficulty integer <= 0, using network target."); } }
                                                        else { double pd_double = json_object_get_double(jdiff); mpf_t nt_f, pd_f, st_f; mpf_inits(nt_f, pd_f, st_f, NULL); mpf_set_z(nt_f, network_target); mpf_set_d(pd_f, pd_double); if (mpf_sgn(pd_f) > 0) { mpf_div(st_f, nt_f, pd_f); mpz_set_f(calculated_share_target, st_f); } else { mpz_set(calculated_share_target, network_target); log_msg("[WARN][SUB] Pool difficulty double <= 0, using network target."); } mpf_clears(nt_f, pd_f, st_f, NULL); }
                                                        const char* target1_hex = "00000000FFFF0000000000000000000000000000000000000000000000000000"; mpz_set_str(target1, target1_hex, 16);
                                                        if (mpz_sgn(calculated_share_target) <= 0) { mpz_set(calculated_share_target, target1); log_msg("[WARN][SUB] Calculated share target <= 0. Using Difficulty 1 target."); }
                                                        else { mpz_set_ui(temp_target, 1); mpz_mul_2exp(temp_target, temp_target, 256); if (mpz_cmp(calculated_share_target, temp_target) >= 0) { mpz_sub_ui(temp_target, temp_target, 1); mpz_set(calculated_share_target, temp_target); log_msg("[WARN][SUB] Calculated share target >= 2^256. Clamping to max target."); } }
                                                        { std::lock_guard<std::mutex> lock(g_share_target_mutex); mpz_set(g_share_target, calculated_share_target); }
                                                        double actual_share_diff = calculate_difficulty_from_target(g_share_target); char* sth = mpz_get_str(NULL, 16, g_share_target); log_msg("[SUB] Updated Share Target to %s (hex). PoolDiff: %.5f -> Actual ShareDiff: %.5f", sth ? sth : "Error", pool_difficulty, actual_share_diff); if (sth) free(sth);
                                                        mpz_clear(calculated_share_target);
                                                    } // end else (valid nBits)
                                                } // end else (nbits != 0)
                                            } catch (const std::exception& e) { log_msg("[ERROR][SUB] C++ Exception during target calculation: %s", e.what()); } catch (...) { log_msg("[ERROR][SUB] Unknown exception during target calculation."); }
                                            mpz_clears(network_target, target1, temp_target, NULL);
                                        } else if (difficulty_ok) { log_msg("[WARN][SUB] Non-positive pool difficulty received: %.5f. Target not updated.", pool_difficulty); }
                                        // ======== CORRECTED TARGET CALCULATION END ========
                                    } else { log_msg("[WARN][SUB] set_difficulty params array is empty or first element is null."); }
                                } else { log_msg("[WARN][SUB] Bad set_difficulty params structure (not array or empty)."); }
                            }
                            // --- END Corrected Difficulty Setting ---
                             else { log_msg("[WARN][SUB] Received unknown notification method: %s", method_name); }
                        } else { log_msg("[WARN][SUB] Received message with no ID and no method: %s", line.c_str()); }
                    } catch (const std::exception& e) { log_msg("[ERROR][SUB] Exception processing message: %s. Line: %s", e.what(), line.c_str()); if (std::string(e.what()).find("Authorization failed") != std::string::npos || std::string(e.what()).find("Subscribe failed") != std::string::npos) { json_object_put(parsed); throw; } } catch (...) { log_msg("[ERROR][SUB] Unknown exception processing message. Line: %s", line.c_str()); }
                    json_object_put(parsed); // Cleanup json object
                 } // end while (processing lines)
            } // end while (connected loop)

            SOCKET old_sock_fd = sock; sock = INVALID_SOCKET;
            if (g_sigint_shutdown.load()) { log_msg("[SUB] Shutdown signal received, exiting."); break; }
            else if (g_sockfd.load(std::memory_order_relaxed) != old_sock_fd && old_sock_fd != INVALID_SOCKET) { log_msg("[SUB] Socket FD %d closed externally. Waiting...", (int)old_sock_fd); }
            else { log_msg("[SUB] Exited receive loop for FD %d. Assuming connection lost.", (int)old_sock_fd); if (!g_connection_lost.load()) { g_connection_lost.store(true); g_new_job_cv.notify_all(); } }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        } // End main while loop
     } catch (const std::runtime_error& e) { log_msg("[FATAL][SUB] Runtime error: %s. Signaling loss.", e.what()); } catch (const std::exception& e) { log_msg("[FATAL][SUB] Standard exception: %s. Signaling loss.", e.what()); } catch (...) { log_msg("[FATAL][SUB] Unknown exception. Signaling loss."); }
     if (!g_connection_lost.load()) { g_connection_lost.store(true); g_new_job_cv.notify_all(); }
     log_msg("[SUB] Subscribe thread finished.");
} // --- End of subscribe_func ---


// --- Periodic Status Logger ---
void log_periodic_status() {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_last_aggregated_report_time);

    // Avoid division by zero or excessive logging if interval is too short
    if (duration.count() < 100) return; // Minimum 100ms interval

    uint64_t total_hashes_now = 0;
    for (const auto& c : g_thread_hash_counts) {
        total_hashes_now += c.load(std::memory_order_relaxed);
    }

    uint64_t prev_total = g_total_hashes_reported.load(std::memory_order_relaxed);
    uint64_t delta_hashes = (total_hashes_now >= prev_total) ? (total_hashes_now - prev_total) : 0; // Handle potential counter reset?

    // Calculate rate in H/s
    double current_rate = (duration.count() > 0) ? (static_cast<double>(delta_hashes) * 1000.0 / duration.count()) : 0.0;

    // Update global state
    g_aggregated_hash_rate.store(current_rate);
    g_total_hashes_reported.store(total_hashes_now); // Update total count reported
    g_last_aggregated_report_time = now;

    // Get other status info (thread-safe reads)
    long height_local = g_current_height.load(std::memory_order_relaxed);
    uint32_t nbits_net_local_le = 0;
    {
        std::lock_guard<std::mutex> lock(g_job_mutex);
        nbits_net_local_le = g_nbits_le; // Read current network nBits under lock
    }

    // Get current share target and calculate its difficulty using GMP
    mpz_t current_share_target_copy;
    mpz_init(current_share_target_copy);
    double difficulty_share_local = 0.0;
    bool target_is_set = false;
    {
        std::lock_guard<std::mutex> lock(g_share_target_mutex);
        if (mpz_sgn(g_share_target) > 0) { // Only calculate if target is set and positive
             mpz_set(current_share_target_copy, g_share_target); // Copy global target
             target_is_set = true;
        }
    } // Release target mutex

    if (target_is_set) {
         difficulty_share_local = calculate_difficulty_from_target(current_share_target_copy);
    }
    mpz_clear(current_share_target_copy);

    // Calculate network difficulty from nBits (if nBits is valid)
    double difficulty_net_local = calculate_difficulty(nbits_net_local_le);

    // Format hashrate for display
    double display_rate = current_rate;
    const char* rate_unit = "H/s";
    if (display_rate >= 1e12) { display_rate /= 1e12; rate_unit = "TH/s"; }
    else if (display_rate >= 1e9) { display_rate /= 1e9; rate_unit = "GH/s"; }
    else if (display_rate >= 1e6) { display_rate /= 1e6; rate_unit = "MH/s"; }
    else if (display_rate >= 1e3) { display_rate /= 1e3; rate_unit = "kH/s"; }

    // Log to file
    log_msg("[STATUS] Height: ~%ld | NetDiff: %.3f | ShareDiff: %.3f | Rate: %.2f %s",
            height_local > 0 ? height_local : 0,
            difficulty_net_local,
            target_is_set ? difficulty_share_local : 0.0, // Show 0 if target not set
            display_rate, rate_unit);

    // Print status to stderr (overwriting previous line)
    fprintf(stderr, "\r%*s\r", 80, ""); // Clear line
    fprintf(stderr, "%s[%s] [STATUS] H: ~%ld | NetD: %.3e | ShareD: %.3f | Rate: %.2f %s%s",
            C_CYAN, timestamp_us().c_str(),
            height_local > 0 ? height_local : 0,
            difficulty_net_local,
            target_is_set ? difficulty_share_local : 0.0,
            display_rate, rate_unit, C_RESET);
    fflush(stderr);
}


// --- Main Function ---
int main() {
    // --- Platform Initialization ---
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    // --- Signal Handling ---
    signal(SIGINT, handle_sigint);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE on POSIX (happens if writing to closed socket)
#endif

    // --- Load Configuration ---
    fprintf(stdout, "Loading configuration from %s...\n", CONFIG_FILE);
    if (!load_config()) {
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    // --- Initialize Global GMP Variables ---
    mpz_init(g_share_target);
    // Initialize share target to Difficulty 1 initially. Pool will override it.
    const char* target1_hex = "00000000FFFF0000000000000000000000000000000000000000000000000000";
    if (mpz_set_str(g_share_target, target1_hex, 16) != 0) {
         log_msg("[FATAL] Failed to initialize g_share_target with Difficulty 1 value.");
         fprintf(stderr, "%s[FATAL] Failed to init GMP target!%s\n", C_RED, C_RESET);
         mpz_clear(g_share_target);
#ifdef _WIN32
         WSACleanup();
#endif
         return 1;
    }
    log_msg("[MAIN] Initialized share target to Difficulty 1 (will be updated by pool).");


    // --- Start Logging ---
    // Clear log file on start? Optional. Current setup appends.
    // std::ofstream clear_log(g_log_file, std::ios::trunc); clear_log.close();
    log_msg("--------------------------------------------------");
    log_msg("Miner starting with configuration:");
    log_msg("  Pool: %s:%d", g_pool_host.c_str(), g_pool_port);
    log_msg("  Wallet/Worker: %s", g_wallet_addr.c_str());
    log_msg("  Password: %s", g_pool_password.empty() ? "[empty]" : "(set)"); // Don't log password itself
    log_msg("  Log File: %s", g_log_file.c_str());
    log_msg("  Threads: %d", g_threads);
    log_msg("--------------------------------------------------");

    // --- Check CPU Features ---
    fprintf(stdout, "Checking CPU features...\n");
    if (!check_cpu_features()) {
        mpz_clear(g_share_target);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    // --- Initialize Global Libraries ---
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        log_msg("[FATAL] curl_global_init failed.");
        mpz_clear(g_share_target);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    // --- Display Basic Info ---
    fprintf(stdout, "%s----------------------------------------%s\n", C_MAG, C_RESET);
    fprintf(stdout, "%s Wallet: %s%s%s\n", C_MAG, C_YELLOW, g_wallet_addr.c_str(), C_RESET);
    fprintf(stdout, "%s Threads: %s%d%s\n", C_MAG, C_YELLOW, g_threads, C_RESET);
    fprintf(stdout, "%s Pool: %s%s:%d%s\n", C_MAG, C_YELLOW, g_pool_host.c_str(), g_pool_port, C_RESET);
    fprintf(stdout, "%s----------------------------------------%s\n", C_MAG, C_RESET);
    fflush(stdout);

    // --- Initialize Hashrate Counters ---
    // Need to resize based on g_threads AFTER loading config
    //g_thread_hash_counts.resize(g_threads);
    g_thread_hash_counts = std::vector<std::atomic<uint64_t>>(g_threads); // <--- 加入這一行，用構造函數初始化大小
    for(auto& c : g_thread_hash_counts) c.store(0); // Initialize counters to 0
    g_total_hashes_reported.store(0);
    g_aggregated_hash_rate.store(0.0);
    g_last_aggregated_report_time = std::chrono::steady_clock::now();

    // --- Get Initial Block Height ---
    log_msg("[MAIN] Fetching initial block height...");
    fprintf(stdout, "[INFO] Fetching initial block height from API...\n"); fflush(stdout);
    long initial_height = get_current_block_height();
    g_current_height.store(initial_height); // Store initial height (-1 if failed)
    if (initial_height > 0) {
        fprintf(stdout, "%s[INFO] Initial block height estimated at: %ld%s\n", C_CYAN, initial_height, C_RESET);
        log_msg("[MAIN] Initial block height from API: %ld", initial_height);
    } else {
        fprintf(stdout, "%s[WARN] Could not fetch initial block height from API.%s\n", C_YELLOW, C_RESET);
        log_msg("[WARN] Failed to fetch initial block height from API.");
    }
    fflush(stdout);

    // --- Timers for Periodic Tasks ---
    const auto height_check_interval = std::chrono::minutes(15); // Check external height periodically
    auto last_height_check_time = std::chrono::steady_clock::now();
    const auto status_log_interval = std::chrono::seconds(STATUS_LOG_INTERVAL_SECONDS);
    auto last_status_log_time = std::chrono::steady_clock::now();


    // --- Main Reconnect Loop ---
    while (!g_sigint_shutdown.load()) {
        log_msg("[MAIN] Attempting connection to pool %s:%d...", g_pool_host.c_str(), g_pool_port);
        fprintf(stdout, "[NET] Connecting to %s:%d...\n", g_pool_host.c_str(), g_pool_port); fflush(stdout);

        // Reset connection lost flag and counters for new attempt
        g_connection_lost.store(false);
        {
            for(auto& c : g_thread_hash_counts) c.store(0);
            g_total_hashes_reported.store(0);
            g_aggregated_hash_rate.store(0.0);
            g_last_aggregated_report_time = std::chrono::steady_clock::now();
        }

        // Attempt connection
        SOCKET sock = connect_pool();

        if (sock == INVALID_SOCKET) {
            log_msg("[MAIN] Connection failed. Retrying in %d seconds...", RECONNECT_DELAY_SECONDS);
            fprintf(stderr, "%s[NET] Connection failed. Retrying in %d seconds...%s\n", C_YELLOW, RECONNECT_DELAY_SECONDS, C_RESET); fflush(stderr);
            // Wait for reconnect delay, but allow shutdown signal to interrupt
            std::unique_lock<std::mutex> lock(g_job_mutex); // Use any mutex for waiting
            g_new_job_cv.wait_for(lock, std::chrono::seconds(RECONNECT_DELAY_SECONDS), []{ return g_sigint_shutdown.load(); });
            if(g_sigint_shutdown.load()) break; // Exit main loop if shutdown during wait
            continue; // Try connecting again
        }

        // --- Connection Successful ---
        g_sockfd.store(sock, std::memory_order_release); // Store the valid socket globally
        log_msg("[MAIN] Connection successful (FD/Socket: %d). Starting threads...", (int)sock);
        fprintf(stdout, "%s[NET] Connected! Starting %d worker threads.%s\n", C_GREEN, g_threads, C_RESET); fflush(stdout);

        // Reset Global Job State Variables (under lock)
        {
            std::lock_guard<std::mutex> lock(g_job_mutex);
            log_msg("[MAIN] Resetting job state for new connection.");
            g_job_id = "";
            g_prevhash_bin.clear();
            g_coinb1_bin.clear();
            g_coinb2_bin.clear();
            g_merkle_branch_bin_be.clear();
            g_version_le = 0;
            g_nbits_le = 0; // Reset nBits
            g_ntime_le = 0;
            g_clean_jobs = false;
            g_new_job_available = false;
            // Also reset extranonce info received from previous connections
            g_extranonce1_bin.clear();
            g_extranonce2_size = 4; // Reset to default
        }
        // Reset Share Target to Diff 1 (pool will send actual difficulty)
        {
            std::lock_guard<std::mutex> target_lock(g_share_target_mutex);
            mpz_set_str(g_share_target, target1_hex, 16); // Use the same hex string for Diff 1
            log_msg("[MAIN] Reset share target to Difficulty 1 for new connection.");
        }

        // Start Threads
        std::thread sub_thread(subscribe_func); // Start subscribe/communication thread
        std::vector<std::thread> miner_threads;
        miner_threads.reserve(g_threads);
        for (int i = 0; i < g_threads; ++i) {
            miner_threads.emplace_back(miner_func, i, g_threads); // Start miner threads
        }

        // --- Monitor Loop (while connected) ---
        while (!g_sigint_shutdown.load() && !g_connection_lost.load()) {
             // Wait for a short duration or until notified of shutdown/disconnect
             std::unique_lock<std::mutex> lock(g_job_mutex); // Use job mutex for CV
             g_new_job_cv.wait_for(lock, std::chrono::seconds(1), // Check every second
                 []{ return g_sigint_shutdown.load() || g_connection_lost.load(); });
             lock.unlock(); // Unlock after waiting

             // Check exit conditions again after wait
             if (g_sigint_shutdown.load() || g_connection_lost.load()) break;

             // Perform periodic tasks
             auto now = std::chrono::steady_clock::now();
             if (now - last_status_log_time >= status_log_interval) {
                 log_periodic_status();
                 last_status_log_time = now;
             }
             if (now - last_height_check_time >= height_check_interval) {
                 log_msg("[MAIN] Performing periodic external height check...");
                 long external_height = get_current_block_height();
                 if (external_height > 0) {
                     long local_height = g_current_height.load();
                     if (external_height > local_height) {
                         log_msg("[MAIN] External height %ld > local height %ld. Updating local height.", external_height, local_height);
                         fprintf(stdout, "\n%s[INFO] External height update detected: %ld%s\n", C_CYAN, external_height, C_RESET); fflush(stdout);
                         g_current_height.store(external_height); // Update atomic height
                     } else if (external_height < local_height && local_height > 0) {
                         // This might happen due to API lag or reorgs, usually ignore unless difference is large
                         log_msg("[WARN][MAIN] External height %ld < local height %ld. Ignoring minor discrepancy.", external_height, local_height);
                     }
                 } else {
                     log_msg("[WARN][MAIN] Periodic external height check failed.");
                 }
                 last_height_check_time = now;
            }
        } // --- End Monitor Loop ---

        // --- Disconnection or Shutdown Detected ---
        if (g_sigint_shutdown.load()) {
             log_msg("[MAIN] Shutdown requested via SIGINT. Stopping threads...");
        }
        else if (g_connection_lost.load()) {
             log_msg("[MAIN] Connection lost detected. Stopping threads and preparing to reconnect...");
             fprintf(stderr, "\r%*s\r%s[%s] Pool connection lost. Reconnecting...%s\n", 80, "", C_YELLOW, timestamp_us().c_str(), C_RESET); fflush(stderr);
        }

        // --- Coordinated Thread Shutdown ---
        // 1. Mark global socket as invalid to prevent further use by subscribe/miner threads
        SOCKET current_fd = g_sockfd.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
        log_msg("[MAIN] Marked global socket FD %d as invalid.", (int)current_fd);

        // 2. Close the socket (this should interrupt blocking reads/selects in subscribe_func)
        if(current_fd != INVALID_SOCKET) {
            log_msg("[MAIN] Closing socket FD %d.", (int)current_fd);
            closesocket(current_fd);
        }

        // 3. Notify all waiting threads (miners waiting for jobs, subscribe?)
        g_new_job_cv.notify_all();
        log_msg("[MAIN] Notified condition variable for thread shutdown.");

        // 4. Join threads
        log_msg("[MAIN] Joining subscribe thread...");
        if (sub_thread.joinable()) { sub_thread.join(); log_msg("[MAIN] Subscribe thread joined."); }
        else { log_msg("[WARN][MAIN] Subscribe thread was not joinable."); }

        log_msg("[MAIN] Joining %d miner threads...", (int)miner_threads.size());
        int joined_count = 0;
        for (auto& t : miner_threads) {
            if (t.joinable()) { t.join(); joined_count++; }
        }
        miner_threads.clear();
        log_msg("[MAIN] Joined %d miner threads.", joined_count);

        // --- Prepare for Next Loop Iteration (Reconnect Delay) ---
        if (g_sigint_shutdown.load()) {
             log_msg("[MAIN] Shutdown confirmed. Exiting main loop.");
             break; // Exit the main reconnect loop
        } else {
             log_msg("[MAIN] Waiting %ds before attempting reconnect...", RECONNECT_DELAY_SECONDS);
             // Wait, allowing interruption by SIGINT
             std::unique_lock<std::mutex> lock(g_job_mutex);
             g_new_job_cv.wait_for(lock, std::chrono::seconds(RECONNECT_DELAY_SECONDS), []{ return g_sigint_shutdown.load(); });
             if (g_sigint_shutdown.load()) break; // Exit if shutdown during wait
        }
    } // --- End Main Reconnect Loop ---

    // --- Final Cleanup ---
    log_msg("[MAIN] Miner shutting down cleanly.");
    fprintf(stdout, "\n%sMiner exiting...%s\n", C_GREEN, C_RESET); fflush(stdout);

    mpz_clear(g_share_target); // Clear global GMP variable
    log_msg("[MAIN] Cleared global GMP variables.");

    curl_global_cleanup(); // Cleanup Curl
#ifdef _WIN32
    WSACleanup(); // Cleanup Winsock
#endif

    // Log final stats
    double final_rate = g_aggregated_hash_rate.load();
    const char* final_unit = "H/s";
    if (final_rate >= 1e12) { final_rate /= 1e12; final_unit = "TH/s"; }
    else if (final_rate >= 1e9) { final_rate /= 1e9; final_unit = "GH/s"; }
    else if (final_rate >= 1e6) { final_rate /= 1e6; final_unit = "MH/s"; }
    else if (final_rate >= 1e3) { final_rate /= 1e3; final_unit = "kH/s"; }
    uint64_t final_hashes = g_total_hashes_reported.load(); // Get last reported total

    fprintf(stdout, "%sFinal Status:%s Rate=%.2f %s | Total Hashes (approx)=%llu%s\n",
            C_CYAN, C_RESET, final_rate, final_unit, final_hashes, C_RESET);
    fflush(stdout);
    log_msg("----------------- Miner Exited -----------------");

    return 0;
}

