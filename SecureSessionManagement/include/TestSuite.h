#pragma once
/**
 * @file TestSuite.h
 * @brief Automated security test suite with exactly 30 test cases.
 *
 * Categories:
 *   A. Registration & Password Security (TC01-TC06)
 *   B. Authentication Security (TC07-TC12)
 *   C. Token Security (TC13-TC22)
 *   D. Session Management (TC23-TC27)
 *   E. Authorization & Robustness (TC28-TC30)
 *
 * All tests use real application components with injectable clock
 * for time-dependent tests. No hardcoded PASS results.
 *
 * Authors: Yash Raj Sinha (1MS24CY071), Shreyanshu Raj (1MS24CY073)
 * Course: 24CYE551 — Secure Coding Using C/C++
 */

#include <string>
#include <vector>
#include <functional>
#include <iostream>

namespace ssm {

/**
 * @struct TestResult
 * @brief Captures the outcome of a single test case.
 */
struct TestResult {
    std::string id;
    std::string name;
    std::string category;
    std::string scenario;
    bool passed;
    std::string actualResult;
};

/**
 * @class TestSuite
 * @brief Runs exactly 30 security test cases against the application.
 */
class TestSuite {
public:
    TestSuite();

    /** Run all 30 test cases and return results. */
    std::vector<TestResult> runAll();

    /** Print a formatted summary of test results. */
    static void printResults(const std::vector<TestResult>& results, std::ostream& out = std::cout);

private:
    // ── Category A: Registration & Password Security ─────────────────────
    TestResult TC01_ValidRegistration();
    TestResult TC02_DuplicateUsername();
    TestResult TC03_EmptyUsername();
    TestResult TC04_EmptyPassword();
    TestResult TC05_WeakPassword();
    TestResult TC06_ExcessiveLengthInput();

    // ── Category B: Authentication Security ──────────────────────────────
    TestResult TC07_ValidLogin();
    TestResult TC08_IncorrectPassword();
    TestResult TC09_NonExistentUsername();
    TestResult TC10_RepeatedFailedLoginLockout();
    TestResult TC11_PasswordChangeWithSessions();
    TestResult TC12_DisabledAccountLogin();

    // ── Category C: Token Security ───────────────────────────────────────
    TestResult TC13_ValidTokenValidation();
    TestResult TC14_CompletelyInvalidToken();
    TestResult TC15_EmptyToken();
    TestResult TC16_MalformedToken();
    TestResult TC17_ModifiedToken();
    TestResult TC18_TokenReplayAfterLogout();
    TestResult TC19_ExpiredTokenReuse();
    TestResult TC20_IdleSessionTimeout();
    TestResult TC21_TokenHashCollisionHandling();
    TestResult TC22_SensitiveInfoLeakage();

    // ── Category D: Session Management ───────────────────────────────────
    TestResult TC23_SessionFixationAttempt();
    TestResult TC24_MultipleActiveSessions();
    TestResult TC25_MaxActiveSessionLimit();
    TestResult TC26_LogoutAllSessions();
    TestResult TC27_RevokedSessionReuse();

    // ── Category E: Authorization & Robustness ───────────────────────────
    TestResult TC28_UserAccessingAdminResource();
    TestResult TC29_CrossUserTokenSubstitution();
    TestResult TC30_AccountDeactivationWithSession();

    /** Helper to create a TestResult. */
    static TestResult makeResult(const std::string& id, const std::string& name,
                                  const std::string& category, const std::string& scenario,
                                  bool passed, const std::string& actual);
};

} // namespace ssm

