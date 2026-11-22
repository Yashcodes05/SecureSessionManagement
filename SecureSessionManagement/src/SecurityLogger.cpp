#include "SecurityLogger.h"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace ssm {

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------
SecurityLogger& SecurityLogger::getInstance()
{
    static SecurityLogger instance;
    return instance;
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
SecurityLogger::SecurityLogger()
    : logFilePath_("security_log.txt")
{
    logFile_.open(logFilePath_, std::ios::app);
}

SecurityLogger::~SecurityLogger()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (logFile_.is_open()) {
        logFile_.close();
    }
}

// ---------------------------------------------------------------------------
// Core logging — thread-safe
// ---------------------------------------------------------------------------
void SecurityLogger::log(LogLevel level, SecurityEvent event,
                         const std::string& username,
                         const std::string& message,
                         const std::string& details)
{
    std::lock_guard<std::mutex> lock(mutex_);

    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level     = level;
    entry.event     = event;
    entry.username  = username;
    entry.message   = message;
    entry.details   = details;

    // Store in memory for programmatic inspection / testing
    memoryLog_.push_back(entry);

    // Persist to disk
    writeToFile(entry);
}

// ---------------------------------------------------------------------------
// Convenience methods
// ---------------------------------------------------------------------------
void SecurityLogger::logLoginSuccess(const std::string& username)
{
    log(LogLevel::INFO, SecurityEvent::LOGIN_SUCCESS, username,
        "User logged in successfully");
}

void SecurityLogger::logLoginFailed(const std::string& username,
                                    const std::string& reason)
{
    // Security note: never include the attempted password in the reason string.
    log(LogLevel::WARNING, SecurityEvent::LOGIN_FAILED, username,
        "Login attempt failed", reason);
}

void SecurityLogger::logLogout(const std::string& username)
{
    log(LogLevel::INFO, SecurityEvent::LOGOUT, username, "User logged out");
}

void SecurityLogger::logInvalidToken(const std::string& partialToken)
{
    // Only log a masked version of the token to avoid leaking credentials.
    log(LogLevel::SECURITY, SecurityEvent::INVALID_TOKEN, "",
        "Invalid token presented", "token=" + maskToken(partialToken));
}

void SecurityLogger::logExpiredSession(const std::string& username)
{
    log(LogLevel::INFO, SecurityEvent::EXPIRED_SESSION, username,
        "Session expired (absolute timeout)");
}

void SecurityLogger::logIdleTimeout(const std::string& username)
{
    log(LogLevel::INFO, SecurityEvent::IDLE_TIMEOUT, username,
        "Session expired (idle timeout)");
}

void SecurityLogger::logRevokedTokenReuse(const std::string& username)
{
    log(LogLevel::SECURITY, SecurityEvent::REVOKED_TOKEN_REUSE, username,
        "Attempt to reuse a revoked session token");
}

void SecurityLogger::logUnauthorizedAccess(const std::string& username,
                                           const std::string& resource)
{
    log(LogLevel::SECURITY, SecurityEvent::UNAUTHORIZED_ACCESS, username,
        "Unauthorized access attempt", "resource=" + resource);
}

void SecurityLogger::logAccountLocked(const std::string& username)
{
    log(LogLevel::SECURITY, SecurityEvent::ACCOUNT_LOCKED, username,
        "Account locked due to repeated failed login attempts");
}

void SecurityLogger::logAccountDisabled(const std::string& username)
{
    log(LogLevel::SECURITY, SecurityEvent::ACCOUNT_DISABLED, username,
        "Account has been disabled");
}

void SecurityLogger::logPasswordChanged(const std::string& username)
{
    // Security note: never log the old or new password / hash.
    log(LogLevel::INFO, SecurityEvent::PASSWORD_CHANGED, username,
        "Password changed successfully");
}

void SecurityLogger::logRegistration(const std::string& username)
{
    log(LogLevel::INFO, SecurityEvent::REGISTRATION, username,
        "New user registered");
}

// ---------------------------------------------------------------------------
// Retrieval helpers
// ---------------------------------------------------------------------------
std::vector<LogEntry> SecurityLogger::getRecentEntries(size_t count) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (count >= memoryLog_.size()) {
        return memoryLog_;
    }
    // Return the last `count` entries.
    return std::vector<LogEntry>(memoryLog_.end() - static_cast<ptrdiff_t>(count),
                                memoryLog_.end());
}

/// Scan every field of every in-memory log entry for the exact substring
/// `sensitiveData`.  Returns true if found — indicating a data leak.
bool SecurityLogger::containsSensitiveData(const std::string& sensitiveData) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (sensitiveData.empty()) {
        return false;
    }

    for (const auto& entry : memoryLog_) {
        if (entry.username.find(sensitiveData) != std::string::npos ||
            entry.message.find(sensitiveData)  != std::string::npos ||
            entry.details.find(sensitiveData)  != std::string::npos) {
            return true;
        }
    }
    return false;
}

void SecurityLogger::clearMemoryLog()
{
    std::lock_guard<std::mutex> lock(mutex_);
    memoryLog_.clear();
}

void SecurityLogger::setLogFile(const std::string& path)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (logFile_.is_open()) {
        logFile_.close();
    }
    logFilePath_ = path;
    logFile_.open(logFilePath_, std::ios::app);
}

// ---------------------------------------------------------------------------
// Token masking — security-critical helper
// ---------------------------------------------------------------------------
/// For tokens of 16 characters or more, reveal only the first 8 hex
/// characters followed by "…".  Shorter tokens are fully replaced with "***"
/// to prevent accidental exposure.
std::string SecurityLogger::maskToken(const std::string& token)
{
    if (token.size() >= 16) {
        return token.substr(0, 8) + "...";
    }
    return "***";
}

// ---------------------------------------------------------------------------
// File output
// ---------------------------------------------------------------------------
void SecurityLogger::writeToFile(const LogEntry& entry)
{
    // Caller already holds mutex_ — do NOT lock again.
    if (!logFile_.is_open()) {
        return;
    }

    logFile_ << "[" << timeToString(entry.timestamp) << "] "
             << "[" << levelToString(entry.level) << "] "
             << "[" << eventToString(entry.event) << "] "
             << "user=\"" << entry.username << "\" "
             << "msg=\"" << entry.message << "\"";

    if (!entry.details.empty()) {
        logFile_ << " details=\"" << entry.details << "\"";
    }
    logFile_ << "\n";
    logFile_.flush();
}

// ---------------------------------------------------------------------------
// String conversion helpers
// ---------------------------------------------------------------------------
std::string SecurityLogger::levelToString(LogLevel level)
{
    switch (level) {
        case LogLevel::INFO:     return "INFO";
        case LogLevel::WARNING:  return "WARNING";
        case LogLevel::SECURITY: return "SECURITY";
        case LogLevel::ERROR:    return "ERROR";
        default:                 return "UNKNOWN";
    }
}

std::string SecurityLogger::eventToString(SecurityEvent event)
{
    switch (event) {
        case SecurityEvent::LOGIN_SUCCESS:          return "LOGIN_SUCCESS";
        case SecurityEvent::LOGIN_FAILED:           return "LOGIN_FAILED";
        case SecurityEvent::LOGOUT:                 return "LOGOUT";
        case SecurityEvent::REGISTRATION:           return "REGISTRATION";
        case SecurityEvent::INVALID_TOKEN:          return "INVALID_TOKEN";
        case SecurityEvent::EXPIRED_SESSION:        return "EXPIRED_SESSION";
        case SecurityEvent::IDLE_TIMEOUT:           return "IDLE_TIMEOUT";
        case SecurityEvent::REVOKED_TOKEN_REUSE:    return "REVOKED_TOKEN_REUSE";
        case SecurityEvent::UNAUTHORIZED_ACCESS:    return "UNAUTHORIZED_ACCESS";
        case SecurityEvent::ACCOUNT_LOCKED:         return "ACCOUNT_LOCKED";
        case SecurityEvent::ACCOUNT_DISABLED:       return "ACCOUNT_DISABLED";
        case SecurityEvent::PASSWORD_CHANGED:       return "PASSWORD_CHANGED";
        case SecurityEvent::SESSION_CREATED:        return "SESSION_CREATED";
        case SecurityEvent::SESSION_DESTROYED:      return "SESSION_DESTROYED";
        case SecurityEvent::ALL_SESSIONS_DESTROYED: return "ALL_SESSIONS_DESTROYED";
        case SecurityEvent::ADMIN_ACTION:           return "ADMIN_ACTION";
        default:                                    return "UNKNOWN";
    }
}

/// Format a time_point as ISO 8601:  YYYY-MM-DDTHH:MM:SSZ
std::string SecurityLogger::timeToString(std::chrono::system_clock::time_point tp)
{
    const std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tmBuf{};
#ifdef _WIN32
    gmtime_s(&tmBuf, &tt);
#else
    gmtime_r(&tt, &tmBuf);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tmBuf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // namespace ssm
