#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <mutex>
#include <chrono>

// Avoid conflict with Windows ERROR macro from wingdi.h
#ifdef ERROR
#undef ERROR
#endif

namespace ssm {

enum class LogLevel {
    INFO,
    WARNING,
    SECURITY,
    ERROR
};

enum class SecurityEvent {
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    LOGOUT,
    REGISTRATION,
    INVALID_TOKEN,
    EXPIRED_SESSION,
    IDLE_TIMEOUT,
    REVOKED_TOKEN_REUSE,
    UNAUTHORIZED_ACCESS,
    ACCOUNT_LOCKED,
    ACCOUNT_DISABLED,
    PASSWORD_CHANGED,
    SESSION_CREATED,
    SESSION_DESTROYED,
    ALL_SESSIONS_DESTROYED,
    ADMIN_ACTION
};

struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    LogLevel level;
    SecurityEvent event;
    std::string username;
    std::string message;
    std::string details;
};

class SecurityLogger {
public:
    // Singleton access
    static SecurityLogger& getInstance();
    
    // Log a security event
    void log(LogLevel level, SecurityEvent event, const std::string& username,
             const std::string& message, const std::string& details = "");
    
    // Convenience methods
    void logLoginSuccess(const std::string& username);
    void logLoginFailed(const std::string& username, const std::string& reason);
    void logLogout(const std::string& username);
    void logInvalidToken(const std::string& partialToken);
    void logExpiredSession(const std::string& username);
    void logIdleTimeout(const std::string& username);
    void logRevokedTokenReuse(const std::string& username);
    void logUnauthorizedAccess(const std::string& username, const std::string& resource);
    void logAccountLocked(const std::string& username);
    void logAccountDisabled(const std::string& username);
    void logPasswordChanged(const std::string& username);
    void logRegistration(const std::string& username);
    
    // Get recent log entries (for testing/inspection)
    std::vector<LogEntry> getRecentEntries(size_t count = 10) const;
    
    // Check if any log entry contains sensitive data (for TC22)
    bool containsSensitiveData(const std::string& sensitiveData) const;
    
    // Clear in-memory log (for test isolation)
    void clearMemoryLog();
    
    // Set log file path
    void setLogFile(const std::string& path);
    
    // Mask a token for safe logging (show first 8 chars only)
    static std::string maskToken(const std::string& token);
    
private:
    SecurityLogger();
    ~SecurityLogger();
    SecurityLogger(const SecurityLogger&) = delete;
    SecurityLogger& operator=(const SecurityLogger&) = delete;
    
    void writeToFile(const LogEntry& entry);
    static std::string levelToString(LogLevel level);
    static std::string eventToString(SecurityEvent event);
    static std::string timeToString(std::chrono::system_clock::time_point tp);
    
    mutable std::mutex mutex_;
    std::vector<LogEntry> memoryLog_;
    std::ofstream logFile_;
    std::string logFilePath_;
};

} // namespace ssm
