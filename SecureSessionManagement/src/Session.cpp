#include "Session.h"
#include <stdexcept>

namespace ssm {

// ---------------------------------------------------------------------------
// Constructor – initialises all session fields from the provided parameters.
//   • lastActivityTime starts equal to creationTime (no activity yet).
//   • expirationTime = creationTime + absoluteTimeout (hard deadline).
//   • Session begins in the ACTIVE state.
// ---------------------------------------------------------------------------
Session::Session(const std::string& sessionId, const std::string& username,
                 const std::string& tokenHash,
                 std::chrono::system_clock::time_point creationTime,
                 std::chrono::seconds absoluteTimeout,
                 std::chrono::seconds idleTimeout)
    : sessionId_(sessionId)
    , username_(username)
    , tokenHash_(tokenHash)
    , status_(SessionStatus::ACTIVE)
    , creationTime_(creationTime)
    , lastActivityTime_(creationTime)                    // no activity yet
    , expirationTime_(creationTime + absoluteTimeout)    // hard expiry wall
    , idleTimeout_(idleTimeout)
{
    if (sessionId.empty()) {
        throw std::invalid_argument("Session ID must not be empty");
    }
    if (username.empty()) {
        throw std::invalid_argument("Username must not be empty");
    }
    if (tokenHash.empty()) {
        throw std::invalid_argument("Token hash must not be empty");
    }
}

// ========================== Getters =======================================

const std::string& Session::getSessionId() const { return sessionId_; }
const std::string& Session::getUsername()  const { return username_;  }
const std::string& Session::getTokenHash() const { return tokenHash_; }
SessionStatus      Session::getStatus()    const { return status_;    }

std::chrono::system_clock::time_point Session::getCreationTime()     const { return creationTime_;     }
std::chrono::system_clock::time_point Session::getLastActivityTime() const { return lastActivityTime_; }
std::chrono::system_clock::time_point Session::getExpirationTime()   const { return expirationTime_;   }
std::chrono::seconds                  Session::getIdleTimeout()      const { return idleTimeout_;      }

// ======================== Session lifecycle ================================

// ---------------------------------------------------------------------------
// updateActivity – refreshes the last-activity timestamp so that the idle
// timer is effectively reset.  Only updates if the session is still ACTIVE;
// revoked / expired sessions cannot be resurrected.
// ---------------------------------------------------------------------------
void Session::updateActivity(std::chrono::system_clock::time_point currentTime) {
    if (status_ == SessionStatus::ACTIVE) {
        lastActivityTime_ = currentTime;
    }
}

// ---------------------------------------------------------------------------
// revoke – permanently marks the session as REVOKED.  This is an
// irreversible administrative action (e.g. forced logout, password change).
// ---------------------------------------------------------------------------
void Session::revoke() {
    status_ = SessionStatus::REVOKED;
}

// ========================== Validation ====================================

// ---------------------------------------------------------------------------
// isExpired – true when the absolute timeout has been exceeded.
// This is a pure check; it does NOT mutate internal state.
// ---------------------------------------------------------------------------
bool Session::isExpired(std::chrono::system_clock::time_point currentTime) const {
    return currentTime >= expirationTime_;
}

// ---------------------------------------------------------------------------
// isIdleTimedOut – true when the time since the last recorded activity
// meets or exceeds the configured idle timeout.
// ---------------------------------------------------------------------------
bool Session::isIdleTimedOut(std::chrono::system_clock::time_point currentTime) const {
    return (currentTime - lastActivityTime_) >= idleTimeout_;
}

// ---------------------------------------------------------------------------
// isRevoked – simple status flag check.
// ---------------------------------------------------------------------------
bool Session::isRevoked() const {
    return status_ == SessionStatus::REVOKED;
}

// ---------------------------------------------------------------------------
// isValid – the primary validation entry-point.  Returns true only when the
// session is ACTIVE *and* neither the absolute nor idle timeout has been
// reached.
//
// SECURITY NOTE: when an expiration or idle-timeout is detected the internal
// status_ is updated so that subsequent calls to getStatus() reflect the
// real state.  status_ is declared mutable for this reason – the logical
// constness of the session object is preserved (we are not changing user-
// visible data, only caching an already-deterministic derivation).
// ---------------------------------------------------------------------------
bool Session::isValid(std::chrono::system_clock::time_point currentTime) const {
    // Already revoked – cannot become valid again.
    if (status_ == SessionStatus::REVOKED) {
        return false;
    }

    // Check absolute expiration first (takes precedence over idle).
    if (isExpired(currentTime)) {
        status_ = SessionStatus::EXPIRED;
        return false;
    }

    // Check idle timeout.
    if (isIdleTimedOut(currentTime)) {
        status_ = SessionStatus::IDLE_TIMEOUT;
        return false;
    }

    // If we were previously marked EXPIRED or IDLE_TIMEOUT but the caller
    // somehow passes an earlier timestamp, we still keep the prior status
    // (defence-in-depth: sessions should not "un-expire").
    if (status_ != SessionStatus::ACTIVE) {
        return false;
    }

    return true;
}

// ======================== Utility =========================================

// ---------------------------------------------------------------------------
// statusToString – human-readable representation for logging / display.
// Never includes sensitive session data.
// ---------------------------------------------------------------------------
std::string Session::statusToString(SessionStatus status) {
    switch (status) {
        case SessionStatus::ACTIVE:       return "ACTIVE";
        case SessionStatus::EXPIRED:      return "EXPIRED";
        case SessionStatus::REVOKED:      return "REVOKED";
        case SessionStatus::IDLE_TIMEOUT: return "IDLE_TIMEOUT";
        default:                          return "UNKNOWN";
    }
}

} // namespace ssm
