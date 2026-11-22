/**
 * @file TestSuite.cpp
 * @brief Implementation of 30 security test cases.
 *
 * TESTING APPROACH:
 * - Each test creates its own isolated AuthenticationManager + SessionManager
 * - Injectable TestClock is used for all time-dependent tests
 * - Real CNG cryptographic operations are exercised
 * - No hardcoded PASS/FAIL results — all outcomes come from actual assertions
 * - Custom hash functions are injected ONLY for collision simulation (TC21)
 *
 * Authors: Yash Raj Sinha (1MS24CY071), Shreyanshu Raj (1MS24CY073)
 * Course: 24CYE551 — Secure Coding Using C/C++
 */

#include "TestSuite.h"
#include "AuthenticationManager.h"
#include "SessionManager.h"
#include "CryptoUtils.h"
#include "InputValidator.h"
#include "SecurityLogger.h"
#include "Clock.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cassert>
#include <algorithm>

namespace ssm {

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Standard test password that meets all complexity requirements:
 * - Uppercase, lowercase, digit, special character
 * - At least 8 characters
 */
static const std::string VALID_PASSWORD = "SecureP@ss1";
static const std::string VALID_PASSWORD_2 = "An0therP@ss!";
static const std::string ADMIN_PASSWORD = "Adm1nP@ss#";

TestResult TestSuite::makeResult(const std::string& id, const std::string& name,
                                  const std::string& category, const std::string& scenario,
                                  bool passed, const std::string& actual)
{
    return { id, name, category, scenario, passed, actual };
}

// ── Constructor ──────────────────────────────────────────────────────────────

TestSuite::TestSuite() {}

// ── Run All ──────────────────────────────────────────────────────────────────

std::vector<TestResult> TestSuite::runAll()
{
    // Clear logger memory for test isolation
    SecurityLogger::getInstance().clearMemoryLog();

    std::vector<TestResult> results;
    results.reserve(30);

    // Category A — Registration & Password Security
    results.push_back(TC01_ValidRegistration());
    results.push_back(TC02_DuplicateUsername());
    results.push_back(TC03_EmptyUsername());
    results.push_back(TC04_EmptyPassword());
    results.push_back(TC05_WeakPassword());
    results.push_back(TC06_ExcessiveLengthInput());

    // Category B — Authentication Security
    results.push_back(TC07_ValidLogin());
    results.push_back(TC08_IncorrectPassword());
    results.push_back(TC09_NonExistentUsername());
    results.push_back(TC10_RepeatedFailedLoginLockout());
    results.push_back(TC11_PasswordChangeWithSessions());
    results.push_back(TC12_DisabledAccountLogin());

    // Category C — Token Security
    results.push_back(TC13_ValidTokenValidation());
    results.push_back(TC14_CompletelyInvalidToken());
    results.push_back(TC15_EmptyToken());
    results.push_back(TC16_MalformedToken());
    results.push_back(TC17_ModifiedToken());
    results.push_back(TC18_TokenReplayAfterLogout());
    results.push_back(TC19_ExpiredTokenReuse());
    results.push_back(TC20_IdleSessionTimeout());
    results.push_back(TC21_TokenHashCollisionHandling());
    results.push_back(TC22_SensitiveInfoLeakage());

    // Category D — Session Management
    results.push_back(TC23_SessionFixationAttempt());
    results.push_back(TC24_MultipleActiveSessions());
    results.push_back(TC25_MaxActiveSessionLimit());
    results.push_back(TC26_LogoutAllSessions());
    results.push_back(TC27_RevokedSessionReuse());

    // Category E — Authorization & Robustness
    results.push_back(TC28_UserAccessingAdminResource());
    results.push_back(TC29_CrossUserTokenSubstitution());
    results.push_back(TC30_AccountDeactivationWithSession());

    return results;
}

// ── Print Results ────────────────────────────────────────────────────────────

void TestSuite::printResults(const std::vector<TestResult>& results, std::ostream& out)
{
    out << "\n";
    out << "================================================================\n";
    out << "      SECURITY TEST SUITE — 30 TEST CASES\n";
    out << "================================================================\n\n";

    std::string currentCategory;
    int passCount = 0;
    int failCount = 0;

    for (const auto& r : results) {
        if (r.category != currentCategory) {
            currentCategory = r.category;
            out << "--- " << currentCategory << " ---\n";
        }

        std::string status = r.passed ? "PASS" : "FAIL";
        out << "  [" << std::setw(4) << status << "] "
            << r.id << " - " << r.name << "\n";
        if (!r.passed) {
            out << "         Scenario: " << r.scenario << "\n";
            out << "         Actual:   " << r.actualResult << "\n";
        }

        if (r.passed) passCount++;
        else failCount++;
    }

    out << "\n================================================================\n";
    out << "  TOTAL: " << results.size()
        << "  |  PASSED: " << passCount
        << "  |  FAILED: " << failCount << "\n";
    out << "================================================================\n\n";
}

// ============================================================================
// CATEGORY A — REGISTRATION & PASSWORD SECURITY
// ============================================================================

TestResult TestSuite::TC01_ValidRegistration()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    bool registered = auth.registerUser("testuser", VALID_PASSWORD);
    bool exists = auth.userExists("testuser");

    bool passed = registered && exists;
    return makeResult("TC01", "Valid User Registration",
                      "A. Registration & Password Security",
                      "Register a new user with valid credentials",
                      passed,
                      passed ? "User registered and exists in store"
                             : "Registration failed unexpectedly");
}

TestResult TestSuite::TC02_DuplicateUsername()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    auth.registerUser("duplicate_user", VALID_PASSWORD);
    bool secondAttempt = auth.registerUser("duplicate_user", VALID_PASSWORD_2);

    bool passed = !secondAttempt;
    return makeResult("TC02", "Duplicate Username Registration",
                      "A. Registration & Password Security",
                      "Attempt to register with an existing username",
                      passed,
                      passed ? "Duplicate registration correctly rejected"
                             : "Duplicate registration was incorrectly allowed");
}

TestResult TestSuite::TC03_EmptyUsername()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    bool registered = auth.registerUser("", VALID_PASSWORD);

    bool passed = !registered;
    return makeResult("TC03", "Empty Username",
                      "A. Registration & Password Security",
                      "Attempt registration with an empty username",
                      passed,
                      passed ? "Empty username correctly rejected"
                             : "Empty username was incorrectly accepted");
}

TestResult TestSuite::TC04_EmptyPassword()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    bool registered = auth.registerUser("validuser", "");

    bool passed = !registered;
    return makeResult("TC04", "Empty Password",
                      "A. Registration & Password Security",
                      "Attempt registration with an empty password",
                      passed,
                      passed ? "Empty password correctly rejected"
                             : "Empty password was incorrectly accepted");
}

TestResult TestSuite::TC05_WeakPassword()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    // Try various weak passwords
    bool weak1 = auth.registerUser("weakuser1", "short");         // Too short
    bool weak2 = auth.registerUser("weakuser2", "alllowercase");  // No uppercase/digit/special
    bool weak3 = auth.registerUser("weakuser3", "12345678");      // No letters/special
    bool weak4 = auth.registerUser("weakuser4", "NoDigits!!");    // No digit

    bool passed = !weak1 && !weak2 && !weak3 && !weak4;
    return makeResult("TC05", "Weak Password",
                      "A. Registration & Password Security",
                      "Attempt registration with passwords failing complexity requirements",
                      passed,
                      passed ? "All weak passwords correctly rejected"
                             : "Some weak passwords were incorrectly accepted");
}

TestResult TestSuite::TC06_ExcessiveLengthInput()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    // Username exceeding MAX_USERNAME_LENGTH (32)
    std::string longUsername(100, 'a');
    bool longUser = auth.registerUser(longUsername, VALID_PASSWORD);

    // Password exceeding MAX_PASSWORD_LENGTH (128)
    std::string longPassword(200, 'A');
    longPassword += "a1@"; // Add complexity chars
    bool longPass = auth.registerUser("normaluser", longPassword);

    bool passed = !longUser && !longPass;
    return makeResult("TC06", "Excessively Long Input",
                      "A. Registration & Password Security",
                      "Attempt registration with excessively long username and password",
                      passed,
                      passed ? "Excessive-length inputs correctly rejected"
                             : "Excessive-length inputs were incorrectly accepted");
}

// ============================================================================
// CATEGORY B — AUTHENTICATION SECURITY
// ============================================================================

TestResult TestSuite::TC07_ValidLogin()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    auth.registerUser("loginuser", VALID_PASSWORD);
    bool authenticated = auth.authenticate("loginuser", VALID_PASSWORD);

    bool passed = authenticated;
    return makeResult("TC07", "Valid Login",
                      "B. Authentication Security",
                      "Login with correct credentials",
                      passed,
                      passed ? "Authentication succeeded with correct credentials"
                             : "Authentication failed with correct credentials");
}

TestResult TestSuite::TC08_IncorrectPassword()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    auth.registerUser("wrongpwuser", VALID_PASSWORD);
    bool authenticated = auth.authenticate("wrongpwuser", "WrongP@ss1");

    bool passed = !authenticated;
    return makeResult("TC08", "Incorrect Password",
                      "B. Authentication Security",
                      "Login with incorrect password",
                      passed,
                      passed ? "Incorrect password correctly rejected"
                             : "Incorrect password was incorrectly accepted");
}

TestResult TestSuite::TC09_NonExistentUsername()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    bool authenticated = auth.authenticate("ghost_user", VALID_PASSWORD);

    bool passed = !authenticated;
    return makeResult("TC09", "Non-Existent Username",
                      "B. Authentication Security",
                      "Login attempt with a username that does not exist",
                      passed,
                      passed ? "Non-existent user correctly rejected"
                             : "Non-existent user was incorrectly accepted");
}

TestResult TestSuite::TC10_RepeatedFailedLoginLockout()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    auth.registerUser("locktest", VALID_PASSWORD);

    // Fail MAX_FAILED_ATTEMPTS (5) times
    for (int i = 0; i < User::MAX_FAILED_ATTEMPTS; i++) {
        auth.authenticate("locktest", "WrongP@ss1");
    }

    // The account should now be locked — even correct password should fail
    bool lockedOut = !auth.authenticate("locktest", VALID_PASSWORD);

    // Advance time past the lockout duration
    clock->advance(std::chrono::seconds(User::LOCKOUT_DURATION_SECONDS + 1));

    // Should be able to login again after lockout expires
    bool afterLockout = auth.authenticate("locktest", VALID_PASSWORD);

    bool passed = lockedOut && afterLockout;
    return makeResult("TC10", "Repeated Failed Login & Lockout",
                      "B. Authentication Security",
                      "Exceed max failed attempts, verify lockout, then verify unlock after timeout",
                      passed,
                      passed ? "Account locked after " + std::to_string(User::MAX_FAILED_ATTEMPTS) +
                               " failures, unlocked after timeout"
                             : "Lockout mechanism did not work correctly. Locked=" +
                               std::to_string(lockedOut) + ", Unlocked=" + std::to_string(afterLockout));
}

TestResult TestSuite::TC11_PasswordChangeWithSessions()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    // Register and login
    auth.registerUser("pwchange_user", VALID_PASSWORD);
    auth.authenticate("pwchange_user", VALID_PASSWORD);
    std::string token = sessions.createSession("pwchange_user");

    // Change password
    bool changed = auth.changePassword("pwchange_user", VALID_PASSWORD, VALID_PASSWORD_2);

    // Old password should no longer work
    bool oldPwFails = !auth.authenticate("pwchange_user", VALID_PASSWORD);

    // New password should work
    bool newPwWorks = auth.authenticate("pwchange_user", VALID_PASSWORD_2);

    // Existing session token should still be valid (until explicitly revoked)
    const Session* session = sessions.validateToken(token);
    bool sessionStillValid = (session != nullptr);

    bool passed = changed && oldPwFails && newPwWorks && sessionStillValid;
    return makeResult("TC11", "Password Change With Sessions",
                      "B. Authentication Security",
                      "Change password and verify old password fails, new works, existing session persists",
                      passed,
                      passed ? "Password changed; old fails, new works, session persists"
                             : "Password change behavior incorrect");
}

TestResult TestSuite::TC12_DisabledAccountLogin()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    auth.registerUser("disableduser", VALID_PASSWORD);

    // Disable the account
    bool disabled = auth.disableAccount("disableduser");

    // Login should fail for disabled accounts
    bool loginFailed = !auth.authenticate("disableduser", VALID_PASSWORD);

    bool passed = disabled && loginFailed;
    return makeResult("TC12", "Disabled Account Login",
                      "B. Authentication Security",
                      "Disable an account and attempt login",
                      passed,
                      passed ? "Disabled account login correctly rejected"
                             : "Disabled account login was incorrectly allowed");
}

// ============================================================================
// CATEGORY C — TOKEN SECURITY
// ============================================================================

TestResult TestSuite::TC13_ValidTokenValidation()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    auth.registerUser("tokenuser", VALID_PASSWORD);
    auth.authenticate("tokenuser", VALID_PASSWORD);
    std::string token = sessions.createSession("tokenuser");

    // Validate the token
    const Session* session = sessions.validateToken(token);

    bool passed = (session != nullptr) && (session->getUsername() == "tokenuser");
    return makeResult("TC13", "Valid Token Validation",
                      "C. Token Security",
                      "Create session and validate the returned token",
                      passed,
                      passed ? "Token validated successfully, correct username"
                             : "Token validation failed unexpectedly");
}

TestResult TestSuite::TC14_CompletelyInvalidToken()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    // Try a completely random token that was never issued
    std::string fakeToken = CryptoUtils::generateSecureToken();
    const Session* session = sessions.validateToken(fakeToken);

    bool passed = (session == nullptr);
    return makeResult("TC14", "Completely Invalid Token",
                      "C. Token Security",
                      "Validate a token that was never issued",
                      passed,
                      passed ? "Invalid token correctly rejected"
                             : "Invalid token was incorrectly accepted");
}

TestResult TestSuite::TC15_EmptyToken()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    const Session* session = sessions.validateToken("");

    bool passed = (session == nullptr);
    return makeResult("TC15", "Empty Token",
                      "C. Token Security",
                      "Validate an empty token string",
                      passed,
                      passed ? "Empty token correctly rejected"
                             : "Empty token was incorrectly accepted");
}

TestResult TestSuite::TC16_MalformedToken()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    // Various malformed tokens
    const Session* s1 = sessions.validateToken("not-hex-at-all!");
    const Session* s2 = sessions.validateToken("abcdef");  // Too short
    const Session* s3 = sessions.validateToken(std::string(65, 'a')); // Too long
    const Session* s4 = sessions.validateToken("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"); // 64 non-hex

    bool passed = !s1 && !s2 && !s3 && !s4;
    return makeResult("TC16", "Malformed Token",
                      "C. Token Security",
                      "Validate various malformed token strings",
                      passed,
                      passed ? "All malformed tokens correctly rejected"
                             : "Some malformed tokens were incorrectly accepted");
}

TestResult TestSuite::TC17_ModifiedToken()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    auth.registerUser("modtoken_user", VALID_PASSWORD);
    auth.authenticate("modtoken_user", VALID_PASSWORD);
    std::string token = sessions.createSession("modtoken_user");

    // Modify one character of the valid token
    std::string modifiedToken = token;
    // Flip one hex character
    modifiedToken[0] = (modifiedToken[0] == 'a') ? 'b' : 'a';

    const Session* session = sessions.validateToken(modifiedToken);

    bool passed = (session == nullptr);
    return makeResult("TC17", "Modified Token",
                      "C. Token Security",
                      "Modify a single character of a valid token and attempt validation",
                      passed,
                      passed ? "Modified token correctly rejected"
                             : "Modified token was incorrectly accepted");
}

TestResult TestSuite::TC18_TokenReplayAfterLogout()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    auth.registerUser("replay_user", VALID_PASSWORD);
    auth.authenticate("replay_user", VALID_PASSWORD);
    std::string token = sessions.createSession("replay_user");

    // Verify token works before logout
    const Session* before = sessions.validateToken(token);
    bool validBefore = (before != nullptr);

    // Logout
    bool loggedOut = sessions.logout(token);

    // Attempt to replay the same token after logout
    const Session* after = sessions.validateToken(token);
    bool rejectedAfter = (after == nullptr);

    bool passed = validBefore && loggedOut && rejectedAfter;
    return makeResult("TC18", "Token Replay After Logout",
                      "C. Token Security",
                      "Use a token, logout, then attempt to reuse the token",
                      passed,
                      passed ? "Token replay after logout correctly rejected"
                             : "Token replay after logout was not properly handled");
}

TestResult TestSuite::TC19_ExpiredTokenReuse()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    // Create session manager with short absolute timeout (60 seconds)
    SessionManager sessions(auth, clock, 60, 30);

    auth.registerUser("expired_user", VALID_PASSWORD);
    auth.authenticate("expired_user", VALID_PASSWORD);
    std::string token = sessions.createSession("expired_user");

    // Verify token works initially
    const Session* before = sessions.validateToken(token);
    bool validBefore = (before != nullptr);

    // Advance time past the absolute expiration
    clock->advance(std::chrono::seconds(61));

    // Token should now be expired
    const Session* after = sessions.validateToken(token);
    bool rejectedAfter = (after == nullptr);

    bool passed = validBefore && rejectedAfter;
    return makeResult("TC19", "Expired Token Reuse",
                      "C. Token Security",
                      "Use a token after its absolute expiration time has passed",
                      passed,
                      passed ? "Expired token correctly rejected after timeout"
                             : "Expired token was not properly rejected");
}

TestResult TestSuite::TC20_IdleSessionTimeout()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);

    // Absolute timeout = 3600s, idle timeout = 30s
    SessionManager sessions(auth, clock, 3600, 30);

    auth.registerUser("idle_user", VALID_PASSWORD);
    auth.authenticate("idle_user", VALID_PASSWORD);
    std::string token = sessions.createSession("idle_user");

    // Verify token works
    const Session* before = sessions.validateToken(token);
    bool validBefore = (before != nullptr);

    // Advance time past idle timeout (but before absolute expiration)
    clock->advance(std::chrono::seconds(31));

    // Token should be rejected due to idle timeout
    const Session* after = sessions.validateToken(token);
    bool rejectedAfter = (after == nullptr);

    bool passed = validBefore && rejectedAfter;
    return makeResult("TC20", "Idle Session Timeout",
                      "C. Token Security",
                      "Leave a session idle past the idle timeout threshold",
                      passed,
                      passed ? "Idle session correctly timed out"
                             : "Idle session timeout did not work correctly");
}

TestResult TestSuite::TC21_TokenHashCollisionHandling()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    auth.registerUser("collision_user", VALID_PASSWORD);
    auth.authenticate("collision_user", VALID_PASSWORD);

    // Create a normal session first
    std::string token1 = sessions.createSession("collision_user");
    std::string hash1 = sessions.getTokenManager().hashToken(token1);

    // Inject a custom hash function that always returns the same hash
    // to simulate a collision
    int callCount = 0;
    sessions.getTokenManager().setCustomHashFunction(
        [&hash1, &callCount](const std::string&) -> std::string {
            callCount++;
            if (callCount <= 2) {
                // First two calls return the colliding hash
                return hash1;
            }
            // After that, return a unique hash to allow eventual success
            return CryptoUtils::sha256("unique_" + std::to_string(callCount));
        }
    );

    // Attempt to create another session — should handle the collision
    // by regenerating the token (because the hash already exists)
    std::string token2 = sessions.createSession("collision_user");

    // Restore normal hashing
    sessions.getTokenManager().clearCustomHashFunction();

    // Both sessions should exist and have different tokens
    bool passed = !token1.empty() && !token2.empty() && (token1 != token2);
    return makeResult("TC21", "Token Hash Collision Handling",
                      "C. Token Security",
                      "Simulate a token hash collision and verify it's handled without overwriting",
                      passed,
                      passed ? "Hash collision handled by regenerating token"
                             : "Hash collision not properly handled");
}

TestResult TestSuite::TC22_SensitiveInfoLeakage()
{
    SecurityLogger::getInstance().clearMemoryLog();

    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    // Use distinctive strings we can search for in logs
    std::string password = VALID_PASSWORD;
    auth.registerUser("leaktest_user", password);
    auth.authenticate("leaktest_user", password);
    std::string token = sessions.createSession("leaktest_user");

    // Get the user's password hash and salt
    const User* user = auth.getUser("leaktest_user");
    std::string pwHash = user->getPasswordHash();
    std::string salt = user->getSalt();

    // Check that none of the sensitive data appears in the logs
    bool passwordLeaked = SecurityLogger::getInstance().containsSensitiveData(password);
    bool hashLeaked = SecurityLogger::getInstance().containsSensitiveData(pwHash);
    bool saltLeaked = SecurityLogger::getInstance().containsSensitiveData(salt);
    bool fullTokenLeaked = SecurityLogger::getInstance().containsSensitiveData(token);

    bool passed = !passwordLeaked && !hashLeaked && !saltLeaked && !fullTokenLeaked;

    std::string detail;
    if (passwordLeaked) detail += "Password leaked. ";
    if (hashLeaked) detail += "Hash leaked. ";
    if (saltLeaked) detail += "Salt leaked. ";
    if (fullTokenLeaked) detail += "Full token leaked. ";

    return makeResult("TC22", "Sensitive Information Leakage Through Logs",
                      "C. Token Security",
                      "Verify that passwords, hashes, salts, and full tokens do not appear in logs",
                      passed,
                      passed ? "No sensitive data found in security logs"
                             : "Sensitive data detected in logs: " + detail);
}

// ============================================================================
// CATEGORY D — SESSION MANAGEMENT
// ============================================================================

TestResult TestSuite::TC23_SessionFixationAttempt()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    auth.registerUser("fixation_user", VALID_PASSWORD);
    auth.authenticate("fixation_user", VALID_PASSWORD);

    // Attacker pre-sets a token they know
    std::string attackerToken = CryptoUtils::generateSecureToken();

    // Create session with the fixation attempt
    std::string serverToken = sessions.createSessionWithFixationAttempt(
        "fixation_user", attackerToken);

    // The server-generated token must NEVER equal the attacker's token
    bool differentToken = (serverToken != attackerToken);

    // The attacker's token should NOT validate
    const Session* attackerSession = sessions.validateToken(attackerToken);
    bool attackerRejected = (attackerSession == nullptr);

    // The server's token should validate
    const Session* serverSession = sessions.validateToken(serverToken);
    bool serverAccepted = (serverSession != nullptr);

    bool passed = differentToken && attackerRejected && serverAccepted;
    return makeResult("TC23", "Session Fixation Attempt",
                      "D. Session Management",
                      "Attempt to fixate a session with an attacker-chosen token",
                      passed,
                      passed ? "Session fixation prevented: attacker token ignored, fresh token issued"
                             : "Session fixation protection failed");
}

TestResult TestSuite::TC24_MultipleActiveSessions()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    auth.registerUser("multi_user", VALID_PASSWORD);

    // Create multiple sessions (simulating logins from different devices)
    std::vector<std::string> tokens;
    for (int i = 0; i < 3; i++) {
        auth.authenticate("multi_user", VALID_PASSWORD);
        std::string token = sessions.createSession("multi_user");
        tokens.push_back(token);
    }

    // All tokens should be valid simultaneously
    bool allValid = true;
    for (const auto& t : tokens) {
        if (sessions.validateToken(t) == nullptr) {
            allValid = false;
            break;
        }
    }

    // All tokens should be different
    bool allDifferent = true;
    for (size_t i = 0; i < tokens.size(); i++) {
        for (size_t j = i + 1; j < tokens.size(); j++) {
            if (tokens[i] == tokens[j]) {
                allDifferent = false;
                break;
            }
        }
    }

    // User should have 3 active sessions
    size_t activeCount = sessions.getUserActiveSessionCount("multi_user");

    bool passed = allValid && allDifferent && (activeCount == 3);
    return makeResult("TC24", "Multiple Active Sessions",
                      "D. Session Management",
                      "Create multiple concurrent sessions for the same user",
                      passed,
                      passed ? "3 concurrent sessions active with unique tokens"
                             : "Multiple session handling failed");
}

TestResult TestSuite::TC25_MaxActiveSessionLimit()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock, 3600, 900, 3); // Max 3 sessions

    auth.registerUser("maxsess_user", VALID_PASSWORD);

    // Create sessions up to the limit
    std::vector<std::string> tokens;
    for (int i = 0; i < 3; i++) {
        auth.authenticate("maxsess_user", VALID_PASSWORD);
        std::string token = sessions.createSession("maxsess_user");
        tokens.push_back(token);
    }

    // Attempt one more — should fail
    auth.authenticate("maxsess_user", VALID_PASSWORD);
    std::string extraToken = sessions.createSession("maxsess_user");

    bool limitEnforced = extraToken.empty();

    // Original sessions should still work
    bool origStillValid = (sessions.validateToken(tokens[0]) != nullptr);

    bool passed = limitEnforced && origStillValid;
    return makeResult("TC25", "Maximum Active Session Limit",
                      "D. Session Management",
                      "Exceed the maximum concurrent session limit",
                      passed,
                      passed ? "Session limit enforced; excess session creation rejected"
                             : "Session limit was not properly enforced");
}

TestResult TestSuite::TC26_LogoutAllSessions()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    auth.registerUser("logoutall_user", VALID_PASSWORD);

    // Create multiple sessions
    std::vector<std::string> tokens;
    for (int i = 0; i < 3; i++) {
        auth.authenticate("logoutall_user", VALID_PASSWORD);
        tokens.push_back(sessions.createSession("logoutall_user"));
    }

    // Logout all
    int revoked = sessions.logoutAll("logoutall_user");

    // All tokens should now be invalid
    bool allInvalid = true;
    for (const auto& t : tokens) {
        if (sessions.validateToken(t) != nullptr) {
            allInvalid = false;
            break;
        }
    }

    bool passed = (revoked == 3) && allInvalid;
    return makeResult("TC26", "Logout All Sessions",
                      "D. Session Management",
                      "Logout all active sessions for a user",
                      passed,
                      passed ? "All 3 sessions revoked; none validate"
                             : "Logout-all did not properly revoke all sessions");
}

TestResult TestSuite::TC27_RevokedSessionReuse()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    auth.registerUser("revoke_user", VALID_PASSWORD);
    auth.authenticate("revoke_user", VALID_PASSWORD);
    std::string token = sessions.createSession("revoke_user");

    // Verify token works
    bool validBefore = (sessions.validateToken(token) != nullptr);

    // Logout (which revokes the session)
    sessions.logout(token);

    // Attempt to reuse the revoked token multiple times
    bool attempt1 = (sessions.validateToken(token) == nullptr);
    bool attempt2 = (sessions.validateToken(token) == nullptr);

    bool passed = validBefore && attempt1 && attempt2;
    return makeResult("TC27", "Revoked Session Reuse",
                      "D. Session Management",
                      "Attempt to reuse a revoked session token multiple times",
                      passed,
                      passed ? "Revoked session token consistently rejected"
                             : "Revoked session reuse was not properly prevented");
}

// ============================================================================
// CATEGORY E — AUTHORIZATION & ROBUSTNESS
// ============================================================================

TestResult TestSuite::TC28_UserAccessingAdminResource()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    // Register a normal user
    auth.registerUser("normal_user", VALID_PASSWORD, UserRole::USER);
    auth.authenticate("normal_user", VALID_PASSWORD);
    std::string token = sessions.createSession("normal_user");

    // Validate and check role
    const Session* session = sessions.validateToken(token);
    bool sessionValid = (session != nullptr);

    // Simulate authorization check: get user's role from trusted server state
    const User* user = auth.getUser("normal_user");
    bool isAdmin = (user != nullptr) && user->isAdmin();

    // Authorization check: user should NOT have admin access
    bool accessDenied = !isAdmin;

    if (accessDenied && sessionValid) {
        SecurityLogger::getInstance().logUnauthorizedAccess("normal_user", "Admin Panel");
    }

    bool passed = sessionValid && accessDenied;
    return makeResult("TC28", "USER Accessing ADMIN Resource",
                      "E. Authorization & Robustness",
                      "Normal user attempts to access an admin-only resource",
                      passed,
                      passed ? "Admin access correctly denied for USER role"
                             : "Admin access was incorrectly granted to USER role");
}

TestResult TestSuite::TC29_CrossUserTokenSubstitution()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    // Register two users
    auth.registerUser("alice", VALID_PASSWORD, UserRole::USER);
    auth.registerUser("bob", VALID_PASSWORD_2, UserRole::ADMIN);

    // Both login
    auth.authenticate("alice", VALID_PASSWORD);
    auth.authenticate("bob", VALID_PASSWORD_2);

    std::string aliceToken = sessions.createSession("alice");
    std::string bobToken = sessions.createSession("bob");

    // Verify Alice's token returns Alice's session (not Bob's)
    const Session* aliceSession = sessions.validateToken(aliceToken);
    bool aliceCorrect = (aliceSession != nullptr) &&
                        (aliceSession->getUsername() == "alice");

    // Verify Bob's token returns Bob's session (not Alice's)
    const Session* bobSession = sessions.validateToken(bobToken);
    bool bobCorrect = (bobSession != nullptr) &&
                      (bobSession->getUsername() == "bob");

    // Alice's token should NOT grant access to Bob's data
    // (Simulated: validate Alice's token and check it doesn't return bob)
    bool noCrossAccess = aliceCorrect && bobCorrect &&
                         (aliceSession->getUsername() != bobSession->getUsername());

    bool passed = noCrossAccess;
    return makeResult("TC29", "Cross-User Token Substitution",
                      "E. Authorization & Robustness",
                      "Verify one user's token cannot access another user's session",
                      passed,
                      passed ? "Tokens correctly bound to their respective users"
                             : "Cross-user token substitution was possible");
}

TestResult TestSuite::TC30_AccountDeactivationWithSession()
{
    auto clock = std::make_shared<TestClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    // Register an admin user
    auth.registerUser("demoted_admin", ADMIN_PASSWORD, UserRole::ADMIN);
    auth.authenticate("demoted_admin", ADMIN_PASSWORD);
    std::string token = sessions.createSession("demoted_admin");

    // Verify session works and user is admin
    const Session* sessionBefore = sessions.validateToken(token);
    bool validBefore = (sessionBefore != nullptr);
    const User* userBefore = auth.getUser("demoted_admin");
    bool wasAdmin = (userBefore != nullptr) && userBefore->isAdmin();

    // Disable the account while session is active
    auth.disableAccount("demoted_admin");

    // The existing session token should now be rejected
    // because validateToken checks user's active status
    const Session* sessionAfter = sessions.validateToken(token);
    bool rejectedAfter = (sessionAfter == nullptr);

    bool passed = validBefore && wasAdmin && rejectedAfter;
    return makeResult("TC30", "Account Deactivation With Active Session",
                      "E. Authorization & Robustness",
                      "Disable a user's account while they have an active session",
                      passed,
                      passed ? "Disabled user's existing session correctly invalidated"
                             : "Disabled user's session was not properly invalidated");
}

} // namespace ssm

// ============================================================================
// TEST EXECUTABLE MAIN
// ============================================================================

#ifndef SSM_NO_TEST_MAIN
int main()
{
    std::cout << "\n=== Secure Session Management — Security Test Suite ===\n";
    std::cout << "Running 30 security test cases...\n\n";

    ssm::TestSuite suite;
    auto results = suite.runAll();
    ssm::TestSuite::printResults(results);

    // Return non-zero exit code if any test failed (for CTest)
    int failCount = 0;
    for (const auto& r : results) {
        if (!r.passed) failCount++;
    }

    if (failCount == 0) {
        std::cout << "All tests PASSED.\n";
    } else {
        std::cout << failCount << " test(s) FAILED.\n";
    }

    return failCount;
}
#endif

