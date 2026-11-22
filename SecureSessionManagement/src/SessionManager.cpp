/**
 * @file SessionManager.cpp
 * @brief Implementation of session lifecycle management.
 *
 * Security implementation notes:
 * - Bearer tokens are NEVER stored — only their SHA-256 hashes
 * - Every login creates a fresh session ID and token (session fixation protection)
 * - Sessions are validated against expiration, idle timeout, and revocation
 * - Maximum concurrent sessions per user is enforced
 * - Expired sessions are cleaned up opportunistically
 * - All session events are logged without exposing secrets
 *
 * Authors: Yash Raj Sinha (1MS24CY071), Shreyanshu Raj (1MS24CY073)
 */

#include "SessionManager.h"
#include "CryptoUtils.h"
#include "SecurityLogger.h"
#include <algorithm>
#include <stdexcept>

namespace ssm {

// ── Constructor ──────────────────────────────────────────────────────────────

SessionManager::SessionManager(AuthenticationManager& authManager,
                               std::shared_ptr<IClock> clock,
                               int absoluteTimeoutSecs,
                               int idleTimeoutSecs,
                               int maxSessionsPerUser)
    : authManager_(authManager)
    , clock_(clock ? clock : std::make_shared<SystemClock>())
    , absoluteTimeoutSecs_(absoluteTimeoutSecs)
    , idleTimeoutSecs_(idleTimeoutSecs)
    , maxSessionsPerUser_(maxSessionsPerUser)
{
}

// ── Session Lifecycle ────────────────────────────────────────────────────────

std::string SessionManager::createSession(const std::string& username)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Verify user exists and is active
    const User* user = authManager_.getUser(username);
    if (!user || !user->isActive()) {
        SecurityLogger::getInstance().log(
            LogLevel::WARNING, SecurityEvent::SESSION_CREATED, username,
            "Session creation failed: user not found or inactive");
        return "";
    }

    // Clean up expired sessions for this user first
    cleanupExpiredSessions(username);

    // Enforce maximum session limit
    size_t activeCount = 0;
    for (const auto& [hash, session] : sessions_) {
        if (session.getUsername() == username && session.isValid(now())) {
            activeCount++;
        }
    }

    if (static_cast<int>(activeCount) >= maxSessionsPerUser_) {
        SecurityLogger::getInstance().log(
            LogLevel::WARNING, SecurityEvent::SESSION_CREATED, username,
            "Session creation failed: maximum sessions reached (" +
            std::to_string(maxSessionsPerUser_) + ")");
        return "";
    }

    // Generate a fresh, unique token — THIS IS THE SESSION FIXATION PROTECTION
    // The token is always generated server-side; never accepted from the client
    std::string rawToken = tokenManager_.generateToken();
    std::string tokenHash = tokenManager_.hashToken(rawToken);

    // Generate a unique session ID (separate from the token)
    std::string sessionId = generateSessionId();

    // Create the session object with the token hash (NOT the raw token)
    Session newSession(
        sessionId,
        username,
        tokenHash,
        now(),
        std::chrono::seconds(absoluteTimeoutSecs_),
        std::chrono::seconds(idleTimeoutSecs_)
    );

    // Register the token hash as active
    tokenManager_.registerTokenHash(tokenHash);

    // Store the session keyed by token hash
    sessions_.emplace(tokenHash, std::move(newSession));
    sessionIdToTokenHash_.emplace(sessionId, tokenHash);

    SecurityLogger::getInstance().log(
        LogLevel::INFO, SecurityEvent::SESSION_CREATED, username,
        "Session created",
        "SessionID: " + sessionId + ", Token: " + SecurityLogger::maskToken(rawToken));

    // Return the raw token to the caller — this is the bearer token
    // It will never be stored server-side again
    return rawToken;
}

const Session* SessionManager::validateToken(const std::string& rawToken)
{
    // Validate token format first
    if (!tokenManager_.isValidTokenFormat(rawToken)) {
        SecurityLogger::getInstance().logInvalidToken(
            SecurityLogger::maskToken(rawToken));
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Hash the incoming token to look up the session
    std::string tokenHash = tokenManager_.hashToken(rawToken);

    auto it = sessions_.find(tokenHash);
    if (it == sessions_.end()) {
        SecurityLogger::getInstance().logInvalidToken(
            SecurityLogger::maskToken(rawToken));
        return nullptr;
    }

    Session& session = it->second;

    // Check if session has been revoked
    if (session.isRevoked()) {
        SecurityLogger::getInstance().logRevokedTokenReuse(session.getUsername());
        return nullptr;
    }

    // Check absolute expiration
    if (session.isExpired(now())) {
        SecurityLogger::getInstance().logExpiredSession(session.getUsername());
        return nullptr;
    }

    // Check idle timeout
    if (session.isIdleTimedOut(now())) {
        SecurityLogger::getInstance().logIdleTimeout(session.getUsername());
        return nullptr;
    }

    // Verify the user is still active (handles disabled accounts with active sessions)
    const User* user = authManager_.getUser(session.getUsername());
    if (!user || !user->isActive()) {
        SecurityLogger::getInstance().log(
            LogLevel::SECURITY, SecurityEvent::UNAUTHORIZED_ACCESS,
            session.getUsername(),
            "Token valid but user account is no longer active");
        return nullptr;
    }

    // Session is valid — update last activity time
    session.updateActivity(now());

    return &session;
}

bool SessionManager::logout(const std::string& rawToken)
{
    if (!tokenManager_.isValidTokenFormat(rawToken)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    std::string tokenHash = tokenManager_.hashToken(rawToken);

    auto it = sessions_.find(tokenHash);
    if (it == sessions_.end()) {
        return false;
    }

    Session& session = it->second;
    std::string username = session.getUsername();

    // Revoke the session
    session.revoke();

    // Unregister the token hash
    tokenManager_.unregisterTokenHash(tokenHash);

    SecurityLogger::getInstance().logLogout(username);

    return true;
}

int SessionManager::logoutAll(const std::string& username)
{
    std::lock_guard<std::mutex> lock(mutex_);

    int revokedCount = 0;

    for (auto& [hash, session] : sessions_) {
        if (session.getUsername() == username && !session.isRevoked()) {
            session.revoke();
            tokenManager_.unregisterTokenHash(hash);
            revokedCount++;
        }
    }

    if (revokedCount > 0) {
        SecurityLogger::getInstance().log(
            LogLevel::INFO, SecurityEvent::ALL_SESSIONS_DESTROYED, username,
            "All sessions destroyed",
            "Revoked " + std::to_string(revokedCount) + " session(s)");
    }

    return revokedCount;
}

bool SessionManager::revokeSession(const std::string& sessionId)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto idIt = sessionIdToTokenHash_.find(sessionId);
    if (idIt == sessionIdToTokenHash_.end()) {
        return false;
    }

    auto sessIt = sessions_.find(idIt->second);
    if (sessIt == sessions_.end()) {
        return false;
    }

    sessIt->second.revoke();
    tokenManager_.unregisterTokenHash(idIt->second);

    SecurityLogger::getInstance().log(
        LogLevel::INFO, SecurityEvent::SESSION_DESTROYED,
        sessIt->second.getUsername(),
        "Session revoked by ID",
        "SessionID: " + sessionId);

    return true;
}

// ── Session Queries ──────────────────────────────────────────────────────────

std::optional<SessionInfo> SessionManager::getSessionInfo(const std::string& rawToken) const
{
    if (!tokenManager_.isValidTokenFormat(rawToken)) {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    std::string tokenHash = tokenManager_.hashToken(rawToken);
    auto it = sessions_.find(tokenHash);
    if (it == sessions_.end()) {
        return std::nullopt;
    }

    const Session& session = it->second;

    // Update session status by checking validity
    session.isValid(now());

    SessionInfo info;
    info.sessionId = session.getSessionId();
    info.username = session.getUsername();
    info.status = session.getStatus();
    info.creationTime = session.getCreationTime();
    info.lastActivityTime = session.getLastActivityTime();
    info.expirationTime = session.getExpirationTime();

    return info;
}

std::vector<SessionInfo> SessionManager::getUserSessions(const std::string& username) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SessionInfo> result;
    for (const auto& [hash, session] : sessions_) {
        if (session.getUsername() == username) {
            SessionInfo info;
            info.sessionId = session.getSessionId();
            info.username = session.getUsername();
            info.status = session.getStatus();
            info.creationTime = session.getCreationTime();
            info.lastActivityTime = session.getLastActivityTime();
            info.expirationTime = session.getExpirationTime();
            result.push_back(info);
        }
    }
    return result;
}

size_t SessionManager::getActiveSessionCount() const
{
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    for (const auto& [hash, session] : sessions_) {
        if (session.isValid(now())) {
            count++;
        }
    }
    return count;
}

size_t SessionManager::getUserActiveSessionCount(const std::string& username) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    for (const auto& [hash, session] : sessions_) {
        if (session.getUsername() == username && session.isValid(now())) {
            count++;
        }
    }
    return count;
}

// ── Token Manager Access ─────────────────────────────────────────────────────

TokenManager& SessionManager::getTokenManager()
{
    return tokenManager_;
}

// ── Configuration ────────────────────────────────────────────────────────────

void SessionManager::setMaxSessionsPerUser(int max)
{
    std::lock_guard<std::mutex> lock(mutex_);
    maxSessionsPerUser_ = max;
}

int SessionManager::getMaxSessionsPerUser() const
{
    return maxSessionsPerUser_;
}

// ── Session Fixation Protection ──────────────────────────────────────────────

std::string SessionManager::createSessionWithFixationAttempt(
    const std::string& username, const std::string& attackerToken)
{
    /**
     * SECURITY: Session fixation protection demonstration.
     *
     * Even though an attacker-supplied token is passed in, we IGNORE it
     * completely and generate a fresh server-side token. This ensures
     * the attacker cannot predict or pre-set the session token.
     *
     * The returned token will NEVER equal the attacker's token.
     */

    // Log the fixation attempt
    SecurityLogger::getInstance().log(
        LogLevel::SECURITY, SecurityEvent::INVALID_TOKEN, username,
        "Session fixation attempt detected — attacker token ignored",
        "Attacker token prefix: " + SecurityLogger::maskToken(attackerToken));

    // Create a legitimate session with a server-generated token
    // The attackerToken is completely ignored
    return createSession(username);
}

// ── Private Helpers ──────────────────────────────────────────────────────────

std::chrono::system_clock::time_point SessionManager::now() const
{
    return clock_->now();
}

void SessionManager::cleanupExpiredSessions(const std::string& username)
{
    // Remove expired/revoked sessions for the given user to free up session slots
    // Note: This is called while mutex_ is already held

    std::vector<std::string> hashesToRemove;

    for (const auto& [hash, session] : sessions_) {
        if (session.getUsername() == username) {
            if (session.isRevoked() || session.isExpired(now()) ||
                session.isIdleTimedOut(now())) {
                hashesToRemove.push_back(hash);
            }
        }
    }

    for (const auto& hash : hashesToRemove) {
        auto sessIt = sessions_.find(hash);
        if (sessIt != sessions_.end()) {
            // Remove from session ID mapping
            auto idIt = sessionIdToTokenHash_.begin();
            while (idIt != sessionIdToTokenHash_.end()) {
                if (idIt->second == hash) {
                    idIt = sessionIdToTokenHash_.erase(idIt);
                } else {
                    ++idIt;
                }
            }
            sessions_.erase(sessIt);
        }
        tokenManager_.unregisterTokenHash(hash);
    }
}

std::string SessionManager::generateSessionId()
{
    // Generate a unique session ID using secure random bytes
    // This is separate from the bearer token for internal tracking
    return "SID-" + CryptoUtils::bytesToHex(CryptoUtils::generateRandomBytes(16));
}

} // namespace ssm

