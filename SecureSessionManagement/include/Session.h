#pragma once
#include <string>
#include <chrono>

namespace ssm {

enum class SessionStatus {
    ACTIVE,
    EXPIRED,
    REVOKED,
    IDLE_TIMEOUT
};

class Session {
public:
    Session(const std::string& sessionId, const std::string& username,
            const std::string& tokenHash,
            std::chrono::system_clock::time_point creationTime,
            std::chrono::seconds absoluteTimeout = std::chrono::seconds(3600),
            std::chrono::seconds idleTimeout = std::chrono::seconds(900));
    
    // Getters
    const std::string& getSessionId() const;
    const std::string& getUsername() const;
    const std::string& getTokenHash() const;
    SessionStatus getStatus() const;
    std::chrono::system_clock::time_point getCreationTime() const;
    std::chrono::system_clock::time_point getLastActivityTime() const;
    std::chrono::system_clock::time_point getExpirationTime() const;
    std::chrono::seconds getIdleTimeout() const;
    
    // Session lifecycle
    void updateActivity(std::chrono::system_clock::time_point currentTime);
    void revoke();
    
    // Validation (checks expiration, idle timeout, revocation)
    bool isValid(std::chrono::system_clock::time_point currentTime) const;
    bool isExpired(std::chrono::system_clock::time_point currentTime) const;
    bool isIdleTimedOut(std::chrono::system_clock::time_point currentTime) const;
    bool isRevoked() const;
    
    // Status string
    static std::string statusToString(SessionStatus status);
    
    // Default timeout configuration
    static constexpr int DEFAULT_ABSOLUTE_TIMEOUT_SECS = 3600;  // 1 hour
    static constexpr int DEFAULT_IDLE_TIMEOUT_SECS = 900;       // 15 minutes
    
private:
    std::string sessionId_;
    std::string username_;
    std::string tokenHash_;
    mutable SessionStatus status_;
    std::chrono::system_clock::time_point creationTime_;
    std::chrono::system_clock::time_point lastActivityTime_;
    std::chrono::system_clock::time_point expirationTime_;
    std::chrono::seconds idleTimeout_;
};

} // namespace ssm
