#pragma once
#include <string>
#include <functional>
#include <unordered_set>
#include <mutex>

namespace ssm {

class TokenManager {
public:
    TokenManager();
    
    // Generate a new unique token. Returns the raw token (not hashed).
    // The raw token is what's given to the user.
    std::string generateToken();
    
    // Hash a token using SHA-256 for storage
    std::string hashToken(const std::string& rawToken) const;
    
    // Validate token format (64 hex chars)
    bool isValidTokenFormat(const std::string& token) const;
    
    // Track active token hashes to ensure uniqueness
    void registerTokenHash(const std::string& tokenHash);
    void unregisterTokenHash(const std::string& tokenHash);
    bool isTokenHashActive(const std::string& tokenHash) const;
    
    // For testing: allow injecting a custom hash function to simulate collisions
    using HashFunction = std::function<std::string(const std::string&)>;
    void setCustomHashFunction(HashFunction func);
    void clearCustomHashFunction();
    
private:
    std::unordered_set<std::string> activeTokenHashes_;
    mutable std::mutex mutex_;
    HashFunction customHashFunc_;
};

} // namespace ssm
