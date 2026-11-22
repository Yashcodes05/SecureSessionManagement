/**
 * @file AuthenticationManager.cpp
 * @brief Implementation of user registration, authentication, and account management.
 *
 * Security implementation notes:
 * - Passwords are NEVER stored in plaintext
 * - Each user gets a unique random salt
 * - PBKDF2-HMAC-SHA256 with 100,000 iterations via Windows CNG
 * - Failed login attempts are tracked with temporary lockout
 * - Constant-time hash comparison prevents timing attacks
 * - All security events are logged (without sensitive data)
 * - Sensitive temporary buffers are cleared after use
 *
 * Authors: Yash Raj Sinha (1MS24CY071), Shreyanshu Raj (1MS24CY073)
 */

#include "AuthenticationManager.h"
#include "CryptoUtils.h"
#include "InputValidator.h"
#include "SecurityLogger.h"
#include <algorithm>

namespace ssm {

// ── Constructor ──────────────────────────────────────────────────────────────

AuthenticationManager::AuthenticationManager(std::shared_ptr<IClock> clock)
    : clock_(clock ? clock : std::make_shared<SystemClock>())
{
}

// ── Registration ─────────────────────────────────────────────────────────────

bool AuthenticationManager::registerUser(const std::string& username,
                                          const std::string& password,
                                          UserRole role)
{
    // Validate username
    auto usernameResult = InputValidator::validateUsername(username);
    if (!usernameResult.valid) {
        SecurityLogger::getInstance().log(
            LogLevel::WARNING, SecurityEvent::REGISTRATION, username,
            "Registration failed: " + usernameResult.errorMessage);
        return false;
    }

    // Validate password strength
    auto passwordResult = InputValidator::validatePassword(password);
    if (!passwordResult.valid) {
        SecurityLogger::getInstance().log(
            LogLevel::WARNING, SecurityEvent::REGISTRATION, username,
            "Registration failed: " + passwordResult.errorMessage);
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Check for duplicate username (case-insensitive comparison)
    std::string lowerUsername = username;
    std::transform(lowerUsername.begin(), lowerUsername.end(),
                   lowerUsername.begin(), ::tolower);

    if (users_.find(lowerUsername) != users_.end()) {
        SecurityLogger::getInstance().log(
            LogLevel::WARNING, SecurityEvent::REGISTRATION, username,
            "Registration failed: username already exists");
        return false;
    }

    // Generate unique salt and hash the password using PBKDF2-HMAC-SHA256
    std::string salt = CryptoUtils::generateSalt();
    std::string passwordHash = CryptoUtils::hashPassword(password, salt);

    // Create the user object
    User newUser(lowerUsername, passwordHash, salt, role);
    users_.emplace(lowerUsername, std::move(newUser));

    // Clear the temporary password hash from our local variable
    CryptoUtils::secureClear(passwordHash);
    CryptoUtils::secureClear(salt);

    SecurityLogger::getInstance().logRegistration(username);
    return true;
}

// ── Authentication ───────────────────────────────────────────────────────────

bool AuthenticationManager::authenticate(const std::string& username,
                                          const std::string& password)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Normalize username
    std::string lowerUsername = username;
    std::transform(lowerUsername.begin(), lowerUsername.end(),
                   lowerUsername.begin(), ::tolower);

    // Look up user
    auto it = users_.find(lowerUsername);
    if (it == users_.end()) {
        // User not found — log but don't reveal which part failed
        SecurityLogger::getInstance().logLoginFailed(username, "Invalid credentials");
        return false;
    }

    User& user = it->second;

    // Check if account is disabled
    if (user.getStatus() == AccountStatus::DISABLED) {
        SecurityLogger::getInstance().logLoginFailed(username, "Account is disabled");
        return false;
    }

    // Check if account is temporarily locked out
    if (user.isLockedOut(now())) {
        SecurityLogger::getInstance().logLoginFailed(username, "Account is locked");
        return false;
    }

    // Hash the provided password with the user's salt and compare
    std::string computedHash = CryptoUtils::hashPassword(password, user.getSalt());
    bool matches = CryptoUtils::constantTimeCompare(computedHash, user.getPasswordHash());

    // Clear the computed hash immediately
    CryptoUtils::secureClear(computedHash);

    if (!matches) {
        // Increment failed login attempts
        user.incrementFailedAttempts();

        if (user.getFailedLoginAttempts() >= User::MAX_FAILED_ATTEMPTS) {
            // Lock the account temporarily
            auto lockUntil = now() + std::chrono::seconds(User::LOCKOUT_DURATION_SECONDS);
            user.lockAccount(lockUntil);
            SecurityLogger::getInstance().logAccountLocked(username);
        }

        SecurityLogger::getInstance().logLoginFailed(username, "Invalid credentials");
        return false;
    }

    // Successful authentication — reset failed attempts
    user.resetFailedAttempts();
    SecurityLogger::getInstance().logLoginSuccess(username);
    return true;
}

// ── Password Management ──────────────────────────────────────────────────────

bool AuthenticationManager::changePassword(const std::string& username,
                                            const std::string& currentPassword,
                                            const std::string& newPassword)
{
    // Validate new password strength
    auto passwordResult = InputValidator::validatePassword(newPassword);
    if (!passwordResult.valid) {
        SecurityLogger::getInstance().log(
            LogLevel::WARNING, SecurityEvent::PASSWORD_CHANGED, username,
            "Password change failed: " + passwordResult.errorMessage);
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    std::string lowerUsername = username;
    std::transform(lowerUsername.begin(), lowerUsername.end(),
                   lowerUsername.begin(), ::tolower);

    auto it = users_.find(lowerUsername);
    if (it == users_.end()) {
        return false;
    }

    User& user = it->second;

    // Verify current password
    std::string computedHash = CryptoUtils::hashPassword(currentPassword, user.getSalt());
    bool matches = CryptoUtils::constantTimeCompare(computedHash, user.getPasswordHash());
    CryptoUtils::secureClear(computedHash);

    if (!matches) {
        SecurityLogger::getInstance().logLoginFailed(username, "Password change: wrong current password");
        return false;
    }

    // Generate new salt and hash for the new password
    std::string newSalt = CryptoUtils::generateSalt();
    std::string newHash = CryptoUtils::hashPassword(newPassword, newSalt);

    user.setPasswordHash(newHash);
    user.setSalt(newSalt);

    // Clear temporaries
    CryptoUtils::secureClear(newHash);
    CryptoUtils::secureClear(newSalt);

    SecurityLogger::getInstance().logPasswordChanged(username);
    return true;
}

// ── Account Management ───────────────────────────────────────────────────────

bool AuthenticationManager::disableAccount(const std::string& username)
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::string lowerUsername = username;
    std::transform(lowerUsername.begin(), lowerUsername.end(),
                   lowerUsername.begin(), ::tolower);

    auto it = users_.find(lowerUsername);
    if (it == users_.end()) {
        return false;
    }

    it->second.setStatus(AccountStatus::DISABLED);
    SecurityLogger::getInstance().logAccountDisabled(username);
    return true;
}

bool AuthenticationManager::enableAccount(const std::string& username)
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::string lowerUsername = username;
    std::transform(lowerUsername.begin(), lowerUsername.end(),
                   lowerUsername.begin(), ::tolower);

    auto it = users_.find(lowerUsername);
    if (it == users_.end()) {
        return false;
    }

    it->second.setStatus(AccountStatus::ACTIVE);
    it->second.resetFailedAttempts();
    return true;
}

bool AuthenticationManager::changeUserRole(const std::string& username, UserRole newRole)
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::string lowerUsername = username;
    std::transform(lowerUsername.begin(), lowerUsername.end(),
                   lowerUsername.begin(), ::tolower);

    auto it = users_.find(lowerUsername);
    if (it == users_.end()) {
        return false;
    }

    it->second.setRole(newRole);

    SecurityLogger::getInstance().log(
        LogLevel::SECURITY, SecurityEvent::ADMIN_ACTION, username,
        "Role changed to " + User::roleToString(newRole));
    return true;
}

// ── Queries ──────────────────────────────────────────────────────────────────

bool AuthenticationManager::userExists(const std::string& username) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::string lowerUsername = username;
    std::transform(lowerUsername.begin(), lowerUsername.end(),
                   lowerUsername.begin(), ::tolower);

    return users_.find(lowerUsername) != users_.end();
}

const User* AuthenticationManager::getUser(const std::string& username) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::string lowerUsername = username;
    std::transform(lowerUsername.begin(), lowerUsername.end(),
                   lowerUsername.begin(), ::tolower);

    auto it = users_.find(lowerUsername);
    if (it == users_.end()) {
        return nullptr;
    }
    return &(it->second);
}

User* AuthenticationManager::getUserMutable(const std::string& username)
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::string lowerUsername = username;
    std::transform(lowerUsername.begin(), lowerUsername.end(),
                   lowerUsername.begin(), ::tolower);

    auto it = users_.find(lowerUsername);
    if (it == users_.end()) {
        return nullptr;
    }
    return &(it->second);
}

std::vector<std::string> AuthenticationManager::getAllUsernames() const
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::string> usernames;
    usernames.reserve(users_.size());
    for (const auto& [name, _] : users_) {
        usernames.push_back(name);
    }
    return usernames;
}

// ── Private ──────────────────────────────────────────────────────────────────

std::chrono::system_clock::time_point AuthenticationManager::now() const
{
    return clock_->now();
}

} // namespace ssm

