#pragma once
/**
 * @file SessionManager.h
 * @brief Manages authenticated sessions, token validation, and session lifecycle.
 *
 * Security responsibilities:
 * - Session creation with fresh, unpredictable identifiers (fixation protection)
 * - Token hashing at rest (never store raw bearer tokens)
 * - Absolute expiration and idle timeout enforcement
 * - Session revocation and logout-all
 * - Maximum active session limit per user
 * - Cross-user token substitution prevention
 *
 * Authors: Yash Raj Sinha (1MS24CY071), Shreyanshu Raj (1MS24CY073)
 * Course: 24CYE551 — Secure Coding Using C/C++
 */

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <memory>
#include <optional>
#include "Session.h"
#include "TokenManager.h"
#include "AuthenticationManager.h"
#include "Clock.h"

namespace ssm {

/**
 * @struct SessionInfo
 * @brief Public-facing session information (no secrets).
 */
struct SessionInfo {
    std::string sessionId;
    std::string username;
    SessionStatus status;
    std::chrono::system_clock::time_point creationTime;
    std::chrono::system_clock::time_point lastActivityTime;
    std::chrono::system_clock::time_point expirationTime;
};

/**
 * @class SessionManager
 * @brief Central session management component.
 *
 * Design:
 * - Sessions are stored in-memory, keyed by token hash
 * - Raw tokens are never stored; only SHA-256 hashes
 * - Every login generates a fresh session ID and token (fixation protection)
 * - Clock is injectable for testing time-dependent behaviors
 */
class SessionManager {
public:
    /**
     * @param authManager Reference to authentication manager for user validation
     * @param clock       Injectable clock (defaults to system clock)
     * @param absoluteTimeoutSecs  Session absolute timeout in seconds (default 3600)
     * @param idleTimeoutSecs      Session idle timeout in seconds (default 900)
     * @param maxSessionsPerUser   Maximum concurrent sessions per user (default 5)
     */
    SessionManager(AuthenticationManager& authManager,
                   std::shared_ptr<IClock> clock = nullptr,
                   int absoluteTimeoutSecs = Session::DEFAULT_ABSOLUTE_TIMEOUT_SECS,
                   int idleTimeoutSecs = Session::DEFAULT_IDLE_TIMEOUT_SECS,
                   int maxSessionsPerUser = 5);

    // ── Session Lifecycle ────────────────────────────────────────────────

    /**
     * Create a new session for an authenticated user.
     * Generates a fresh token and session ID (session fixation protection).
     * @return The raw bearer token to give to the user, or empty string on failure.
     */
    std::string createSession(const std::string& username);

    /**
     * Validate a bearer token.
     * Hashes the token, looks up the session, checks expiration/idle/revocation.
     * Updates last activity on success.
     * @return Pointer to the session if valid, nullptr otherwise.
     */
    const Session* validateToken(const std::string& rawToken);

    /**
     * Logout: revoke the session associated with the given token.
     * @return true if the session was found and revoked.
     */
    bool logout(const std::string& rawToken);

    /**
     * Logout all sessions for a given user.
     * @return Number of sessions revoked.
     */
    int logoutAll(const std::string& username);

    /**
     * Revoke a specific session by session ID (admin action).
     * @return true if the session was found and revoked.
     */
    bool revokeSession(const std::string& sessionId);

    // ── Session Queries ──────────────────────────────────────────────────

    /** Get information about a session by token. */
    std::optional<SessionInfo> getSessionInfo(const std::string& rawToken) const;

    /** Get all active sessions for a user. */
    std::vector<SessionInfo> getUserSessions(const std::string& username) const;

    /** Get total active session count. */
    size_t getActiveSessionCount() const;

    /** Get active session count for a specific user. */
    size_t getUserActiveSessionCount(const std::string& username) const;

    // ── Token Manager Access ─────────────────────────────────────────────

    /** Get reference to the internal token manager (for testing). */
    TokenManager& getTokenManager();

    // ── Configuration ────────────────────────────────────────────────────

    /** Set the maximum sessions per user. */
    void setMaxSessionsPerUser(int max);
    int getMaxSessionsPerUser() const;

    // ── Session Fixation Protection ──────────────────────────────────────

    /**
     * Attempt session fixation: try to create a session with a pre-set token.
     * This MUST fail — always generates a fresh token internally.
     * (Exposed for testing TC23 to demonstrate that fixation is not possible.)
     * @return The server-generated token (never the attacker-supplied one).
     */
    std::string createSessionWithFixationAttempt(const std::string& username,
                                                  const std::string& attackerToken);

private:
    AuthenticationManager& authManager_;
    TokenManager tokenManager_;
    std::shared_ptr<IClock> clock_;

    // Sessions keyed by token hash
    std::unordered_map<std::string, Session> sessions_;

    // Session ID to token hash mapping (for revokeSession by ID)
    std::unordered_map<std::string, std::string> sessionIdToTokenHash_;

    mutable std::mutex mutex_;

    int absoluteTimeoutSecs_;
    int idleTimeoutSecs_;
    int maxSessionsPerUser_;

    /** Get current time from the injectable clock. */
    std::chrono::system_clock::time_point now() const;

    /** Clean up expired sessions for a user (internal). */
    void cleanupExpiredSessions(const std::string& username);

    /** Generate a unique session ID. */
    std::string generateSessionId();
};

} // namespace ssm

