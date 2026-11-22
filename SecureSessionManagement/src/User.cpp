#include "User.h"

namespace ssm {

// ---------------------------------------------------------------------------
// Constructor — initialises a new user with sensible defaults
// ---------------------------------------------------------------------------
User::User(const std::string& username, const std::string& passwordHash,
           const std::string& salt, UserRole role)
    : username_(username)
    , passwordHash_(passwordHash)
    , salt_(salt)
    , role_(role)
    , status_(AccountStatus::ACTIVE)
    , failedLoginAttempts_(0)
    , lockoutUntil_(std::chrono::system_clock::time_point::min())
{
}

// ---------------------------------------------------------------------------
// Getters
// ---------------------------------------------------------------------------
const std::string& User::getUsername() const { return username_; }
const std::string& User::getPasswordHash() const { return passwordHash_; }
const std::string& User::getSalt() const { return salt_; }
UserRole User::getRole() const { return role_; }
AccountStatus User::getStatus() const { return status_; }
int User::getFailedLoginAttempts() const { return failedLoginAttempts_; }
std::chrono::system_clock::time_point User::getLockoutTime() const { return lockoutUntil_; }

// ---------------------------------------------------------------------------
// Setters
// ---------------------------------------------------------------------------
void User::setPasswordHash(const std::string& hash) { passwordHash_ = hash; }
void User::setSalt(const std::string& salt) { salt_ = salt; }
void User::setRole(UserRole role) { role_ = role; }
void User::setStatus(AccountStatus status) { status_ = status; }

// ---------------------------------------------------------------------------
// Login attempt tracking
// ---------------------------------------------------------------------------

/// Record one more failed login attempt.
void User::incrementFailedAttempts()
{
    ++failedLoginAttempts_;
}

/// Reset the counter after a successful login.
void User::resetFailedAttempts()
{
    failedLoginAttempts_ = 0;
}

/// Lock the account until the specified point in time.
void User::lockAccount(std::chrono::system_clock::time_point lockUntil)
{
    status_ = AccountStatus::LOCKED;
    lockoutUntil_ = lockUntil;
}

/// Returns true when the account is LOCKED and the lockout period has not
/// yet elapsed.  If the lockout has expired the status is transparently
/// switched back to ACTIVE so subsequent checks succeed immediately.
bool User::isLockedOut(std::chrono::system_clock::time_point currentTime) const
{
    if (status_ != AccountStatus::LOCKED) {
        return false;
    }
    if (currentTime >= lockoutUntil_) {
        // Lockout period has expired — logically the account is active again.
        // We cast away const here intentionally so the caller does not have to
        // remember to unlock the account manually after every check.
        const_cast<User*>(this)->status_ = AccountStatus::ACTIVE;
        const_cast<User*>(this)->failedLoginAttempts_ = 0;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Role / status helpers
// ---------------------------------------------------------------------------
bool User::isAdmin() const { return role_ == UserRole::ADMIN; }
bool User::isActive() const { return status_ == AccountStatus::ACTIVE; }

// ---------------------------------------------------------------------------
// String conversion helpers
// ---------------------------------------------------------------------------
std::string User::roleToString(UserRole role)
{
    switch (role) {
        case UserRole::USER:  return "USER";
        case UserRole::ADMIN: return "ADMIN";
        default:              return "UNKNOWN";
    }
}

std::string User::statusToString(AccountStatus status)
{
    switch (status) {
        case AccountStatus::ACTIVE:   return "ACTIVE";
        case AccountStatus::LOCKED:   return "LOCKED";
        case AccountStatus::DISABLED: return "DISABLED";
        default:                      return "UNKNOWN";
    }
}

} // namespace ssm
