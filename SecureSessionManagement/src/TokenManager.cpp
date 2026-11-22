#include "TokenManager.h"
#include "CryptoUtils.h"
#include "InputValidator.h"

#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <mutex>

namespace ssm {

// ---------------------------------------------------------------------------
// Constructor – no special initialisation required; the unordered_set and
// mutex are default-constructed.
// ---------------------------------------------------------------------------
TokenManager::TokenManager() = default;

// ---------------------------------------------------------------------------
// generateToken – produces a cryptographically random, unique token.
//
// ALGORITHM:
//   1. Generate 32 random bytes via CryptoUtils::generateSecureToken()
//      (returned as a 64-character lowercase hex string).
//   2. Hash the raw token with SHA-256 (or the injected test hash func).
//   3. Check whether the hash already exists in the active set.
//      – If it does (astronomically unlikely with a good CSPRNG, but
//        handled for defence-in-depth), regenerate.  Give up after
//        MAX_RETRIES attempts to avoid infinite loops.
//   4. Return the *raw* token to the caller.  The hash is NOT registered
//      here – that responsibility belongs to the SessionManager which
//      coordinates creation of the Session object.
//
// SECURITY: the raw token is returned to the caller (and ultimately to
// the authenticated user).  Only the *hash* should ever be persisted.
// ---------------------------------------------------------------------------
std::string TokenManager::generateToken() {
    constexpr int MAX_RETRIES = 10;

    std::lock_guard<std::mutex> lock(mutex_);

    for (int attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        // Step 1 – generate a 64-hex-char cryptographically random token.
        std::string rawToken = CryptoUtils::generateSecureToken();

        // Step 2 – compute the storage hash.
        std::string hash;
        if (customHashFunc_) {
            hash = customHashFunc_(rawToken);
        } else {
            hash = CryptoUtils::sha256(rawToken);
        }

        // Step 3 – verify uniqueness among currently active sessions.
        if (activeTokenHashes_.find(hash) == activeTokenHashes_.end()) {
            return rawToken;   // unique – hand it back
        }

        // Hash collision detected – loop and retry.
        // NOTE: we intentionally do NOT log the token or hash value.
    }

    // All retries exhausted – this should never happen with a properly
    // seeded CSPRNG and SHA-256, but we fail loudly rather than silently.
    throw std::runtime_error(
        "TokenManager::generateToken – failed to produce a unique token "
        "after maximum retries; possible CSPRNG or hash function issue");
}

// ---------------------------------------------------------------------------
// hashToken – returns the SHA-256 hex digest of `rawToken`.
// Uses the injected custom hash function when one has been set (testing).
// ---------------------------------------------------------------------------
std::string TokenManager::hashToken(const std::string& rawToken) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (customHashFunc_) {
        return customHashFunc_(rawToken);
    }
    return CryptoUtils::sha256(rawToken);
}

// ---------------------------------------------------------------------------
// isValidTokenFormat – a raw token is valid if it is exactly 64 lowercase
// hexadecimal characters (representing 32 bytes).
// ---------------------------------------------------------------------------
bool TokenManager::isValidTokenFormat(const std::string& token) const {
    if (token.length() != 64) {
        return false;
    }
    return std::all_of(token.cbegin(), token.cend(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

// ======================== Active-hash tracking ============================

// ---------------------------------------------------------------------------
// registerTokenHash – adds a token hash to the active set.
// Called by SessionManager when a new session is created.
// ---------------------------------------------------------------------------
void TokenManager::registerTokenHash(const std::string& tokenHash) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeTokenHashes_.insert(tokenHash);
}

// ---------------------------------------------------------------------------
// unregisterTokenHash – removes a token hash from the active set.
// Called when a session is destroyed, expired, or revoked.
// ---------------------------------------------------------------------------
void TokenManager::unregisterTokenHash(const std::string& tokenHash) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeTokenHashes_.erase(tokenHash);
}

// ---------------------------------------------------------------------------
// isTokenHashActive – checks whether the given hash is currently tracked.
// ---------------------------------------------------------------------------
bool TokenManager::isTokenHashActive(const std::string& tokenHash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return activeTokenHashes_.find(tokenHash) != activeTokenHashes_.end();
}

// =================== Test-support: custom hash injection ==================

// ---------------------------------------------------------------------------
// setCustomHashFunction – replaces the default SHA-256 hash with `func`.
// Intended exclusively for unit tests (e.g. simulating hash collisions).
// ---------------------------------------------------------------------------
void TokenManager::setCustomHashFunction(HashFunction func) {
    std::lock_guard<std::mutex> lock(mutex_);
    customHashFunc_ = std::move(func);
}

// ---------------------------------------------------------------------------
// clearCustomHashFunction – restores the default SHA-256 hash.
// ---------------------------------------------------------------------------
void TokenManager::clearCustomHashFunction() {
    std::lock_guard<std::mutex> lock(mutex_);
    customHashFunc_ = nullptr;
}

} // namespace ssm
