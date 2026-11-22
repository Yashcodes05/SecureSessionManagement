#pragma once
/**
 * @file AuthenticationManager.h
 * @brief Manages user registration, authentication, and account security.
 *
 * Security responsibilities:
 * - Secure password hashing with PBKDF2-HMAC-SHA256 via CNG
 * - Duplicate-user rejection
 * - Failed-login tracking with temporary lockout
 * - Account disabling/enabling
 * - Password change with session awareness
 *
 * Authors: Yash Raj Sinha (1MS24CY071), Shreyanshu Raj (1MS24CY073)
 * Course: 24CYE551 — Secure Coding Using C/C++
 */

#include <string>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <vector>
#include "User.h"
#include "Clock.h"

namespace ssm {

/**
 * @class AuthenticationManager
 * @brief Handles user registration, login, password changes, and account management.
 *
 * Design decisions:
 * - Users are stored in an in-memory map (prototype — production would use a database)
 * - All password operations use CryptoUtils for PBKDF2-HMAC-SHA256
 * - Thread-safe via mutex
 * - Clock is injectable for testing time-dependent lockouts
 */
class AuthenticationManager {
public:
    /**
     * @param clock Injectable clock for testing lockout timing.
     *              Defaults to system clock if nullptr.
     */
    explicit AuthenticationManager(std::shared_ptr<IClock> clock = nullptr);

    // ── Registration ─────────────────────────────────────────────────────

    /**
     * Register a new user with the given credentials.
     * @return true if registration succeeds, false if username taken or invalid.
     */
    bool registerUser(const std::string& username, const std::string& password,
                      UserRole role = UserRole::USER);

    // ── Authentication ───────────────────────────────────────────────────

    /**
     * Authenticate a user with username and password.
     * Tracks failed attempts and enforces lockout.
     * @return true if authentication succeeds.
     */
    bool authenticate(const std::string& username, const std::string& password);

    // ── Password Management ──────────────────────────────────────────────

    /**
     * Change a user's password. Requires the current password for verification.
     * @return true if the password was changed successfully.
     */
    bool changePassword(const std::string& username,
                        const std::string& currentPassword,
                        const std::string& newPassword);

    // ── Account Management ───────────────────────────────────────────────

    /**
     * Disable a user account (admin action).
     * @return true if the account was disabled.
     */
    bool disableAccount(const std::string& username);

    /**
     * Enable a previously disabled user account.
     * @return true if the account was enabled.
     */
    bool enableAccount(const std::string& username);

    /**
     * Change a user's role (admin action).
     * @return true if the role was changed.
     */
    bool changeUserRole(const std::string& username, UserRole newRole);

    // ── Queries ──────────────────────────────────────────────────────────

    /** Check if a user exists. */
    bool userExists(const std::string& username) const;

    /** Get a const pointer to a user (nullptr if not found). */
    const User* getUser(const std::string& username) const;

    /** Get a mutable pointer to a user (nullptr if not found). */
    User* getUserMutable(const std::string& username);

    /** Get all registered usernames. */
    std::vector<std::string> getAllUsernames() const;

private:
    std::unordered_map<std::string, User> users_;
    mutable std::mutex mutex_;
    std::shared_ptr<IClock> clock_;

    /** Get the current time from the injectable clock. */
    std::chrono::system_clock::time_point now() const;
};

} // namespace ssm

