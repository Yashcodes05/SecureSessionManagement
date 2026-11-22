#pragma once

// ============================================================================
// CryptoUtils.h — Cryptographic utility class using Windows CNG (BCrypt) APIs
// 
// Provides: secure random generation, SHA-256 hashing, PBKDF2 password
// hashing, constant-time comparison, and secure buffer clearing.
//
// All cryptographic operations delegate to Windows CNG which is FIPS 140-2
// validated. No user-space crypto implementations are used.
// ============================================================================

#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>

// Windows CNG headers
#include <windows.h>
#include <bcrypt.h>

namespace ssm {

// ============================================================================
// CngAlgorithmHandle — RAII wrapper for BCRYPT_ALG_HANDLE
//
// Ensures BCryptCloseAlgorithmProvider is always called, even on exceptions.
// Non-copyable, move-only to prevent double-close.
// ============================================================================
class CngAlgorithmHandle {
public:
    CngAlgorithmHandle() noexcept : handle_(nullptr) {}

    /// Open an algorithm provider.
    /// @param algorithmId  e.g. BCRYPT_SHA256_ALGORITHM, BCRYPT_RNG_ALGORITHM
    /// @param flags        e.g. BCRYPT_ALG_HANDLE_HMAC_FLAG for HMAC variants
    explicit CngAlgorithmHandle(LPCWSTR algorithmId, ULONG flags = 0) : handle_(nullptr) {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&handle_, algorithmId, nullptr, flags);
        if (!BCRYPT_SUCCESS(status)) {
            throw std::runtime_error("BCryptOpenAlgorithmProvider failed with NTSTATUS: "
                                     + std::to_string(static_cast<long>(status)));
        }
    }

    ~CngAlgorithmHandle() noexcept {
        if (handle_) {
            BCryptCloseAlgorithmProvider(handle_, 0);
            handle_ = nullptr;
        }
    }

    // Non-copyable
    CngAlgorithmHandle(const CngAlgorithmHandle&) = delete;
    CngAlgorithmHandle& operator=(const CngAlgorithmHandle&) = delete;

    // Movable
    CngAlgorithmHandle(CngAlgorithmHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    CngAlgorithmHandle& operator=(CngAlgorithmHandle&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                BCryptCloseAlgorithmProvider(handle_, 0);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    /// Get the raw handle for passing to CNG functions.
    BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }

    /// Check if the handle is valid.
    explicit operator bool() const noexcept { return handle_ != nullptr; }

private:
    BCRYPT_ALG_HANDLE handle_;
};

// ============================================================================
// CryptoUtils — Static-only cryptographic utility class
//
// Design decisions:
// - Static class (no instances) because crypto utilities are stateless
// - All methods throw std::runtime_error on CNG failures
// - Sensitive buffers are cleared with SecureZeroMemory before destruction
// - Hex encoding used for token/salt portability (no binary storage issues)
// ============================================================================
class CryptoUtils {
public:
    // ---- Random Generation ----

    /// Generate cryptographically secure random bytes using BCryptGenRandom.
    /// @param numBytes  Number of random bytes to produce
    /// @return Vector of random bytes
    /// @throws std::runtime_error if BCryptGenRandom fails
    static std::vector<uint8_t> generateRandomBytes(size_t numBytes);

    /// Generate a 256-bit (32-byte) session token, returned as a 64-char hex string.
    /// 256 bits provides sufficient entropy against brute-force attacks.
    static std::string generateSecureToken();

    // ---- Hashing ----

    /// Compute SHA-256 hash of a string, returned as a 64-char lowercase hex string.
    static std::string sha256(const std::string& input);

    /// Compute SHA-256 hash of raw bytes, returned as a 64-char lowercase hex string.
    static std::string sha256(const std::vector<uint8_t>& data);

    // ---- Password Hashing ----

    /// Generate a 16-byte random salt, returned as a 32-char hex string.
    /// 16 bytes (128 bits) provides sufficient uniqueness for password salts.
    static std::string generateSalt();

    /// Hash a password using PBKDF2-HMAC-SHA256.
    /// @param password    The plaintext password (will be securely handled)
    /// @param salt        Hex-encoded salt string
    /// @param iterations  PBKDF2 iteration count (default: 100,000)
    /// @return Hex-encoded derived key (32 bytes = 64 hex chars)
    static std::string hashPassword(const std::string& password, const std::string& salt, int iterations = 100000);

    // ---- Comparison ----

    /// Constant-time string comparison to prevent timing side-channel attacks.
    /// Both strings are compared in full regardless of where they differ.
    static bool constantTimeCompare(const std::string& a, const std::string& b);

    // ---- Encoding Utilities ----

    /// Convert a byte vector to a lowercase hex string.
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);

    /// Convert a hex string to a byte vector.
    /// @throws std::invalid_argument if hex string has odd length or invalid chars
    static std::vector<uint8_t> hexToBytes(const std::string& hex);

    // ---- Secure Cleanup ----

    /// Securely zero a std::string buffer using SecureZeroMemory.
    /// Prevents compiler from optimizing away the memset.
    static void secureClear(std::string& str);

    /// Securely zero a std::vector<uint8_t> buffer using SecureZeroMemory.
    static void secureClear(std::vector<uint8_t>& vec);

private:
    // Static-only class — no instantiation allowed
    CryptoUtils() = delete;
};

} // namespace ssm
