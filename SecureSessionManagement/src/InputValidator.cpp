// ============================================================================
// InputValidator.cpp — Implementation of input validation and sanitization
//
// Security principles applied:
// - Whitelist validation: only explicitly allowed characters are accepted
// - Length bounds: all inputs are checked against min/max constants
// - Fail-closed: ambiguous or malformed input is rejected
// - No exceptions thrown for invalid input (returns ValidationResult instead)
// - Null byte rejection: prevents string truncation attacks
// - Safe integer parsing: uses std::stoi with exception handling
// ============================================================================

#include "InputValidator.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <sstream>
#include <string>

namespace ssm {

// ============================================================================
// validateUsername
//
// Rules:
//   - Length: 3 to 32 characters (MIN_USERNAME_LENGTH..MAX_USERNAME_LENGTH)
//   - Allowed characters: a-z, A-Z, 0-9, underscore (_)
//   - No leading or trailing whitespace
//
// Rationale: Restricting to alphanumeric + underscore prevents SQL injection,
// XSS, path traversal, and other injection attacks at the input boundary.
// ============================================================================
ValidationResult InputValidator::validateUsername(const std::string& username) {
    // Check for leading/trailing whitespace first
    if (!username.empty() && (std::isspace(static_cast<unsigned char>(username.front())) ||
                              std::isspace(static_cast<unsigned char>(username.back())))) {
        return {false, "Username must not have leading or trailing spaces"};
    }

    // Check length bounds
    if (username.length() < MIN_USERNAME_LENGTH) {
        return {false, "Username must be at least " + std::to_string(MIN_USERNAME_LENGTH) + " characters"};
    }
    if (username.length() > MAX_USERNAME_LENGTH) {
        return {false, "Username must be at most " + std::to_string(MAX_USERNAME_LENGTH) + " characters"};
    }

    // Whitelist validation: only alphanumeric and underscore
    for (char ch : username) {
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_') {
            return {false, "Username may only contain letters, digits, and underscores"};
        }
    }

    return {true, ""};
}

// ============================================================================
// validatePassword
//
// Rules:
//   - Length: 8 to 128 characters
//   - Must contain at least one uppercase letter (A-Z)
//   - Must contain at least one lowercase letter (a-z)
//   - Must contain at least one digit (0-9)
//   - Must contain at least one special character (non-alphanumeric)
//
// These rules enforce a minimum password complexity to resist dictionary
// and brute-force attacks. The 128-char upper limit prevents denial-of-service
// via extremely long passwords being fed to PBKDF2.
// ============================================================================
ValidationResult InputValidator::validatePassword(const std::string& password) {
    if (password.length() < MIN_PASSWORD_LENGTH) {
        return {false, "Password must be at least " + std::to_string(MIN_PASSWORD_LENGTH) + " characters"};
    }
    if (password.length() > MAX_PASSWORD_LENGTH) {
        return {false, "Password must be at most " + std::to_string(MAX_PASSWORD_LENGTH) + " characters"};
    }

    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (char ch : password) {
        unsigned char uch = static_cast<unsigned char>(ch);
        if (std::isupper(uch)) hasUpper = true;
        else if (std::islower(uch)) hasLower = true;
        else if (std::isdigit(uch)) hasDigit = true;
        else hasSpecial = true;  // Any non-alphanumeric is "special"
    }

    if (!hasUpper) {
        return {false, "Password must contain at least one uppercase letter"};
    }
    if (!hasLower) {
        return {false, "Password must contain at least one lowercase letter"};
    }
    if (!hasDigit) {
        return {false, "Password must contain at least one digit"};
    }
    if (!hasSpecial) {
        return {false, "Password must contain at least one special character"};
    }

    return {true, ""};
}

// ============================================================================
// validateTokenFormat
//
// A valid session token is exactly 64 lowercase hex characters (representing
// 32 bytes / 256 bits). This matches the output of CryptoUtils::generateSecureToken().
//
// Accepting only lowercase hex prevents case-sensitivity issues in comparisons.
// ============================================================================
ValidationResult InputValidator::validateTokenFormat(const std::string& token) {
    if (token.length() != TOKEN_HEX_LENGTH) {
        return {false, "Token must be exactly " + std::to_string(TOKEN_HEX_LENGTH) + " hex characters"};
    }

    for (char ch : token) {
        // Accept only lowercase hex: 0-9 and a-f
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return {false, "Token must contain only lowercase hex characters (0-9, a-f)"};
        }
    }

    return {true, ""};
}

// ============================================================================
// validateMenuChoice
//
// Safely parses user input as an integer and checks that it falls within
// the valid menu range [minVal, maxVal].
//
// Uses std::stoi with try/catch to handle non-numeric input gracefully
// instead of undefined behaviour.
// ============================================================================
ValidationResult InputValidator::validateMenuChoice(const std::string& input, int minVal, int maxVal) {
    if (input.empty()) {
        return {false, "Input cannot be empty"};
    }

    // Reject strings that are too long to be a reasonable integer
    if (input.length() > 10) {
        return {false, "Invalid menu choice"};
    }

    int choice = 0;
    try {
        size_t pos = 0;
        choice = std::stoi(input, &pos);

        // Ensure the entire string was consumed (no trailing junk)
        if (pos != input.length()) {
            return {false, "Invalid menu choice: contains non-numeric characters"};
        }
    } catch (const std::invalid_argument&) {
        return {false, "Invalid menu choice: not a number"};
    } catch (const std::out_of_range&) {
        return {false, "Invalid menu choice: number out of range"};
    }

    if (choice < minVal || choice > maxVal) {
        return {false, "Choice must be between " + std::to_string(minVal) +
                        " and " + std::to_string(maxVal)};
    }

    return {true, ""};
}

// ============================================================================
// sanitizeInput
//
// Operations:
//   1. Reject strings containing null bytes (prevents string truncation attacks
//      where embedded \0 causes C-string functions to see a shorter string)
//   2. Trim leading and trailing whitespace
//
// Returns an empty string if null bytes are detected, signalling rejection.
// ============================================================================
std::string InputValidator::sanitizeInput(const std::string& input) {
    // Reject null bytes — these can cause string truncation vulnerabilities
    // when the std::string is later converted to a C-string
    for (char ch : input) {
        if (ch == '\0') {
            return "";
        }
    }

    // Find the first non-whitespace character
    size_t start = 0;
    while (start < input.length() && std::isspace(static_cast<unsigned char>(input[start]))) {
        ++start;
    }

    // Find the last non-whitespace character
    size_t end = input.length();
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) {
        --end;
    }

    return input.substr(start, end - start);
}

// ============================================================================
// readLineSafe
//
// Reads a single line from the input stream, enforcing a maximum character
// limit to prevent memory exhaustion from extremely long input lines.
//
// Behaviour:
//   - Reads character by character up to maxLength
//   - Stops at newline or EOF
//   - If the line exceeds maxLength, remaining characters up to the newline
//     are discarded (the stream is drained) to prevent desynchronisation
//   - Returns the truncated line (up to maxLength characters)
// ============================================================================
std::string InputValidator::readLineSafe(std::istream& in, size_t maxLength) {
    std::string result;
    result.reserve(std::min(maxLength, static_cast<size_t>(256)));

    char ch = 0;
    size_t count = 0;
    bool truncated = false;

    while (in.get(ch)) {
        // Stop at newline (don't include it in the result)
        if (ch == '\n') {
            break;
        }

        // Skip carriage return (handle \r\n line endings on Windows)
        if (ch == '\r') {
            continue;
        }

        if (count < maxLength) {
            result.push_back(ch);
            ++count;
        } else {
            // Line exceeds max length — drain remaining characters to the
            // next newline to keep the stream in a consistent state
            truncated = true;
        }
    }

    // The truncated flag is intentionally not surfaced to the caller here;
    // the caller receives the first maxLength characters. If stricter handling
    // is needed, this could be extended to return a ValidationResult.
    (void)truncated;

    return result;
}

} // namespace ssm
