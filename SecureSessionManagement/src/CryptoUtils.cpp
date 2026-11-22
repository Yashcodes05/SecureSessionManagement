// ============================================================================
// CryptoUtils.cpp — Implementation of cryptographic utilities using Windows CNG
//
// All cryptographic operations use the Windows CNG (Cryptography: Next
// Generation) API which is FIPS 140-2 validated. This avoids any user-space
// crypto that could be vulnerable to implementation flaws.
//
// Security notes:
// - Every sensitive buffer (passwords, hashes, keys) is zeroed with
//   SecureZeroMemory before going out of scope.
// - CNG algorithm handles are managed via RAII (CngAlgorithmHandle).
// - Hash object buffers are heap-allocated and cleaned up in scope guards.
// - NTSTATUS is checked after every CNG call; failures throw exceptions
//   rather than returning error codes (fail-loud policy).
// ============================================================================

#include "CryptoUtils.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <string>
#include <vector>
#include <cstdint>

// Backup linkage directive in case CMake target_link_libraries is not used
#pragma comment(lib, "bcrypt.lib")

namespace ssm {

// ============================================================================
// generateRandomBytes — Fill a vector with cryptographically secure random data
//
// Uses BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG which does not
// require opening an algorithm provider, simplifying error handling.
// ============================================================================
std::vector<uint8_t> CryptoUtils::generateRandomBytes(size_t numBytes) {
    if (numBytes == 0) {
        return {};
    }

    std::vector<uint8_t> buffer(numBytes, 0);

    // BCRYPT_USE_SYSTEM_PREFERRED_RNG allows passing nullptr as the provider,
    // using the OS default CSPRNG. This is the recommended approach for random
    // byte generation on modern Windows.
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buffer.data(),
        static_cast<ULONG>(numBytes),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status)) {
        // Securely clear partial output before throwing
        SecureZeroMemory(buffer.data(), buffer.size());
        throw std::runtime_error("BCryptGenRandom failed with NTSTATUS: "
                                 + std::to_string(static_cast<long>(status)));
    }

    return buffer;
}

// ============================================================================
// generateSecureToken — 256-bit random session token as hex string
//
// 32 bytes = 256 bits of entropy, returned as 64-char hex string.
// This exceeds OWASP's recommendation of at least 128 bits for session IDs.
// ============================================================================
std::string CryptoUtils::generateSecureToken() {
    auto bytes = generateRandomBytes(32);
    std::string token = bytesToHex(bytes);

    // Clear the raw bytes now that we have the hex representation
    secureClear(bytes);

    return token;
}

// ============================================================================
// sha256 (string overload) — SHA-256 of a UTF-8 string
// ============================================================================
std::string CryptoUtils::sha256(const std::string& input) {
    std::vector<uint8_t> data(input.begin(), input.end());
    std::string result = sha256(data);
    secureClear(data);
    return result;
}

// ============================================================================
// sha256 (vector overload) — SHA-256 of raw bytes
//
// Implementation:
//   1. Open BCRYPT_SHA256_ALGORITHM provider
//   2. Query hash object size and hash length
//   3. Create hash object, feed data, finalize
//   4. Clean up all intermediate buffers
//
// The hash object buffer is allocated on the heap because its size is
// determined at runtime by the CNG provider.
// ============================================================================
std::string CryptoUtils::sha256(const std::vector<uint8_t>& data) {
    // Open the SHA-256 algorithm provider (RAII managed)
    CngAlgorithmHandle algorithm(BCRYPT_SHA256_ALGORITHM);

    // Query the size of the hash object buffer
    DWORD hashObjectSize = 0;
    DWORD cbResult = 0;
    NTSTATUS status = BCryptGetProperty(
        algorithm.get(),
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hashObjectSize),
        sizeof(hashObjectSize),
        &cbResult,
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGetProperty(OBJECT_LENGTH) failed: "
                                 + std::to_string(static_cast<long>(status)));
    }

    // Query the hash output length (should be 32 for SHA-256)
    DWORD hashLength = 0;
    status = BCryptGetProperty(
        algorithm.get(),
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashLength),
        sizeof(hashLength),
        &cbResult,
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGetProperty(HASH_LENGTH) failed: "
                                 + std::to_string(static_cast<long>(status)));
    }

    // Allocate the hash object buffer
    std::vector<uint8_t> hashObject(hashObjectSize, 0);

    // Create the hash object
    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(
        algorithm.get(),
        &hHash,
        hashObject.data(),
        hashObjectSize,
        nullptr,    // No HMAC key for plain SHA-256
        0,
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        SecureZeroMemory(hashObject.data(), hashObject.size());
        throw std::runtime_error("BCryptCreateHash failed: "
                                 + std::to_string(static_cast<long>(status)));
    }

    // Feed the input data into the hash
    status = BCryptHashData(
        hHash,
        const_cast<PUCHAR>(data.data()),
        static_cast<ULONG>(data.size()),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        SecureZeroMemory(hashObject.data(), hashObject.size());
        throw std::runtime_error("BCryptHashData failed: "
                                 + std::to_string(static_cast<long>(status)));
    }

    // Finalize the hash and retrieve the digest
    std::vector<uint8_t> hashValue(hashLength, 0);
    status = BCryptFinishHash(
        hHash,
        hashValue.data(),
        hashLength,
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        SecureZeroMemory(hashObject.data(), hashObject.size());
        SecureZeroMemory(hashValue.data(), hashValue.size());
        throw std::runtime_error("BCryptFinishHash failed: "
                                 + std::to_string(static_cast<long>(status)));
    }

    // Clean up the hash handle
    BCryptDestroyHash(hHash);

    // Convert digest to hex string
    std::string result = bytesToHex(hashValue);

    // Securely clear intermediate buffers
    SecureZeroMemory(hashObject.data(), hashObject.size());
    SecureZeroMemory(hashValue.data(), hashValue.size());

    return result;
}

// ============================================================================
// generateSalt — 16-byte (128-bit) random salt as hex string
//
// 128 bits is sufficient to ensure uniqueness across all password entries.
// Stored as hex for easy serialization/comparison.
// ============================================================================
std::string CryptoUtils::generateSalt() {
    auto bytes = generateRandomBytes(16);
    std::string salt = bytesToHex(bytes);
    secureClear(bytes);
    return salt;
}

// ============================================================================
// hashPassword — PBKDF2-HMAC-SHA256 key derivation
//
// Uses BCryptDeriveKeyPBKDF2 which requires opening the SHA-256 algorithm
// with the BCRYPT_ALG_HANDLE_HMAC_FLAG.
//
// Parameters:
// - password:   plaintext password (handled carefully, cleared after use)
// - salt:       hex-encoded salt string (decoded to raw bytes internally)
// - iterations: default 100,000 per OWASP 2023 recommendations
//
// Output: 32-byte (256-bit) derived key returned as 64-char hex string.
//
// Security: The plaintext password bytes are SecureZeroMemory'd immediately
// after the derivation call completes.
// ============================================================================
std::string CryptoUtils::hashPassword(const std::string& password, const std::string& salt, int iterations) {
    if (iterations <= 0) {
        throw std::invalid_argument("PBKDF2 iteration count must be positive");
    }

    // Open SHA-256 with HMAC flag for PBKDF2
    CngAlgorithmHandle algorithm(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);

    // Decode the hex salt to raw bytes
    std::vector<uint8_t> saltBytes = hexToBytes(salt);

    // Copy password to a mutable buffer so we can SecureZeroMemory it
    std::vector<uint8_t> passwordBytes(password.begin(), password.end());

    // Derived key buffer: 32 bytes (256 bits)
    const ULONG derivedKeyLength = 32;
    std::vector<uint8_t> derivedKey(derivedKeyLength, 0);

    // Perform PBKDF2 derivation
    NTSTATUS status = BCryptDeriveKeyPBKDF2(
        algorithm.get(),
        passwordBytes.data(),
        static_cast<ULONG>(passwordBytes.size()),
        saltBytes.data(),
        static_cast<ULONG>(saltBytes.size()),
        static_cast<ULONGLONG>(iterations),
        derivedKey.data(),
        derivedKeyLength,
        0
    );

    // Immediately clear the plaintext password bytes regardless of success/failure
    SecureZeroMemory(passwordBytes.data(), passwordBytes.size());
    SecureZeroMemory(saltBytes.data(), saltBytes.size());

    if (!BCRYPT_SUCCESS(status)) {
        SecureZeroMemory(derivedKey.data(), derivedKey.size());
        throw std::runtime_error("BCryptDeriveKeyPBKDF2 failed: "
                                 + std::to_string(static_cast<long>(status)));
    }

    // Convert derived key to hex
    std::string result = bytesToHex(derivedKey);

    // Clear the raw derived key
    SecureZeroMemory(derivedKey.data(), derivedKey.size());

    return result;
}

// ============================================================================
// constantTimeCompare — Timing-attack-resistant string comparison
//
// Compares every byte of both strings regardless of where a mismatch occurs.
// This prevents an attacker from determining the correct prefix of a token
// by measuring response time.
//
// Returns false immediately if lengths differ (length is not secret for our
// use cases — tokens and hashes have fixed, known lengths).
// ============================================================================
bool CryptoUtils::constantTimeCompare(const std::string& a, const std::string& b) {
    // Length difference is not considered secret information for fixed-length
    // tokens and hashes, so an early return here is acceptable.
    if (a.size() != b.size()) {
        return false;
    }

    // XOR accumulator: will be non-zero if any byte differs
    volatile unsigned char result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }

    return result == 0;
}

// ============================================================================
// bytesToHex — Convert raw bytes to lowercase hex string
// ============================================================================
std::string CryptoUtils::bytesToHex(const std::vector<uint8_t>& bytes) {
    static constexpr char hexChars[] = "0123456789abcdef";

    std::string hex;
    hex.reserve(bytes.size() * 2);

    for (uint8_t byte : bytes) {
        hex.push_back(hexChars[(byte >> 4) & 0x0F]);
        hex.push_back(hexChars[byte & 0x0F]);
    }

    return hex;
}

// ============================================================================
// hexToBytes — Convert hex string to raw bytes
//
// Validates that the input contains only valid hex characters and has even
// length. Throws std::invalid_argument on malformed input.
// ============================================================================
std::vector<uint8_t> CryptoUtils::hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t high = 0;
        uint8_t low = 0;

        // Parse high nibble
        char ch = hex[i];
        if (ch >= '0' && ch <= '9') {
            high = static_cast<uint8_t>(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            high = static_cast<uint8_t>(ch - 'a' + 10);
        } else if (ch >= 'A' && ch <= 'F') {
            high = static_cast<uint8_t>(ch - 'A' + 10);
        } else {
            throw std::invalid_argument("Invalid hex character: " + std::string(1, ch));
        }

        // Parse low nibble
        ch = hex[i + 1];
        if (ch >= '0' && ch <= '9') {
            low = static_cast<uint8_t>(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            low = static_cast<uint8_t>(ch - 'a' + 10);
        } else if (ch >= 'A' && ch <= 'F') {
            low = static_cast<uint8_t>(ch - 'A' + 10);
        } else {
            throw std::invalid_argument("Invalid hex character: " + std::string(1, ch));
        }

        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }

    return bytes;
}

// ============================================================================
// secureClear — Zero sensitive buffers using SecureZeroMemory
//
// SecureZeroMemory is a Windows intrinsic that the compiler is guaranteed
// not to optimize away, unlike memset which can be elided if the buffer
// is not read after clearing.
// ============================================================================
void CryptoUtils::secureClear(std::string& str) {
    if (!str.empty()) {
        // SecureZeroMemory is guaranteed not to be optimized out
        SecureZeroMemory(&str[0], str.size());
        str.clear();
    }
}

void CryptoUtils::secureClear(std::vector<uint8_t>& vec) {
    if (!vec.empty()) {
        SecureZeroMemory(vec.data(), vec.size());
        vec.clear();
    }
}

} // namespace ssm
