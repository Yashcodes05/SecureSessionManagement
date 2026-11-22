#pragma once
#include <string>
#include <chrono>

namespace ssm {

// User roles for role-based access control
enum class UserRole {
    USER,
    ADMIN
};

// Account status
enum class AccountStatus {
    ACTIVE,
    LOCKED,       // Temporarily locked due to failed login attempts
    DISABLED      // Administratively disabled
};

class User {
public:
    User(const std::string& username, const std::string& passwordHash,
         const std::string& salt, UserRole role = UserRole::USER);
    
    // Getters
    const std::string& getUsername() const;
    const std::string& getPasswordHash() const;
    const std::string& getSalt() const;
    UserRole getRole() const;
    AccountStatus getStatus() const;
    int getFailedLoginAttempts() const;
    std::chrono::system_clock::time_point getLockoutTime() const;
    
    // Setters
    void setPasswordHash(const std::string& hash);
    void setSalt(const std::string& salt);
    void setRole(UserRole role);
    void setStatus(AccountStatus status);
    
    // Login attempt tracking
    void incrementFailedAttempts();
    void resetFailedAttempts();
    void lockAccount(std::chrono::system_clock::time_point lockUntil);
    bool isLockedOut(std::chrono::system_clock::time_point currentTime) const;
    
    // Role helpers
    bool isAdmin() const;
    bool isActive() const;
    
    // String conversion helpers
    static std::string roleToString(UserRole role);
    static std::string statusToString(AccountStatus status);
    
    // Configuration
    static constexpr int MAX_FAILED_ATTEMPTS = 5;
    static constexpr int LOCKOUT_DURATION_SECONDS = 300; // 5 minutes
    
private:
    std::string username_;
    std::string passwordHash_;
    std::string salt_;
    UserRole role_;
    AccountStatus status_;
    int failedLoginAttempts_;
    std::chrono::system_clock::time_point lockoutUntil_;
};

} // namespace ssm
