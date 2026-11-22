#pragma once

// ============================================================================
// InputValidator.h — Input validation and sanitization utilities
//
// Provides strict validation for all user-facing inputs to prevent injection
// attacks, buffer overflows, and malformed data from reaching core logic.
//
// Security principles:
// - Whitelist validation: only explicitly allowed characters pass
// - Length enforcement: all inputs bounded by min/max constants
// - Fail-closed: any ambiguity results in rejection
// ============================================================================

#include <string>
#include <iostream>

namespace ssm {

/// Result of a validation check, carrying success/failure and a reason string.
struct ValidationResult {
    bool valid;
    std::string errorMessage;
};

// ============================================================================
// InputValidator — Static-only input validation class
//
// All methods are pure functions with no side effects, making them safe to
// call from any thread.
// ============================================================================
class InputValidator {
public:
    /// Validate a username string.
    /// Rules: 3-32 chars, alphanumeric + underscore only, no leading/trailing spaces.
    static ValidationResult validateUsername(const std::string& username);

    /// Validate a password string.
    /// Rules: 8-128 chars, must contain at least one uppercase letter,
    /// one lowercase letter, one digit, and one special character.
    static ValidationResult validatePassword(const std::string& password);

    /// Validate a session token format.
    /// Rules: exactly 64 lowercase hex characters (representing 32 bytes).
    static ValidationResult validateTokenFormat(const std::string& token);

    /// Validate a menu choice string as an integer within [minVal, maxVal].
    static ValidationResult validateMenuChoice(const std::string& input, int minVal, int maxVal);

    /// Sanitize user input: trim leading/trailing whitespace, reject null bytes.
    /// @return Sanitized string, or empty string if null bytes found.
    static std::string sanitizeInput(const std::string& input);

    /// Safely read a line from an input stream with maximum length enforcement.
    /// Truncates at maxLength characters to prevent excessive memory allocation.
    /// @param in         Input stream to read from
    /// @param maxLength  Maximum number of characters to accept (default: 256)
    /// @return The line read (up to maxLength chars), without newline
    static std::string readLineSafe(std::istream& in, size_t maxLength = 256);

    // ---- Configuration Constants ----

    static constexpr size_t MIN_USERNAME_LENGTH = 3;
    static constexpr size_t MAX_USERNAME_LENGTH = 32;
    static constexpr size_t MIN_PASSWORD_LENGTH = 8;
    static constexpr size_t MAX_PASSWORD_LENGTH = 128;
    static constexpr size_t TOKEN_HEX_LENGTH = 64;   // 32 bytes = 64 hex chars
    static constexpr size_t MAX_INPUT_LENGTH = 256;

private:
    // Static-only class — no instantiation allowed
    InputValidator() = delete;
};

} // namespace ssm
