/**
 * @file main.cpp
 * @brief Console application for Secure Session Management demonstration.
 *
 * Provides an interactive menu-driven interface that exercises all security
 * components: registration, authentication, token management, session
 * lifecycle, role-based access control, and automated security testing.
 *
 * Menu Operations:
 *  1. Register User       — Create a new account with validated credentials
 *  2. Login               — Authenticate and receive a session token
 *  3. Access Protected Resource  — Demonstrates token validation
 *  4. Access Admin Resource      — Demonstrates role-based authorization
 *  5. View Session Status        — Shows session details (without secrets)
 *  6. Logout                     — Revoke the current session
 *  7. Logout All Sessions        — Revoke all sessions for current user
 *  8. Change Password            — Change password for the current user
 *  9. Run All 30 Security Tests  — Execute the automated test suite
 * 10. Exit
 *
 * Authors: Yash Raj Sinha (1MS24CY071), Shreyanshu Raj (1MS24CY073)
 * Course: 24CYE551 — Secure Coding Using C/C++
 * Guide:  Prof. Shankaramma
 */

#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <ctime>

#include "AuthenticationManager.h"
#include "SessionManager.h"
#include "SecurityLogger.h"
#include "InputValidator.h"
#include "CryptoUtils.h"
#include "TestSuite.h"
#include "Clock.h"

using namespace ssm;

// ── Console Helpers ──────────────────────────────────────────────────────────

/** Clear the screen (Windows). */
static void clearScreen()
{
    // Fallback: print newlines (portable)
    std::cout << std::string(50, '\n');
}

/** Print a separator line. */
static void printSeparator()
{
    std::cout << "------------------------------------------------------------\n";
}

/** Format a time_point as a readable local time string. */
static std::string formatTime(std::chrono::system_clock::time_point tp)
{
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    struct tm localTm;
#ifdef _WIN32
    localtime_s(&localTm, &t);
#else
    localtime_r(&t, &localTm);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &localTm);
    return std::string(buf);
}

/** Read a line from stdin safely. */
static std::string readInput(const std::string& prompt, bool maskInput = false)
{
    std::cout << prompt;
    std::string input;

    if (maskInput) {
        // For passwords — we read normally in console mode
        // (True masking requires platform-specific APIs)
        std::getline(std::cin, input);
    } else {
        std::getline(std::cin, input);
    }

    return InputValidator::sanitizeInput(input);
}

/** Print the main menu. */
static void printMenu()
{
    std::cout << "\n";
    printSeparator();
    std::cout << "  SECURE SESSION MANAGEMENT SYSTEM\n";
    std::cout << "  Yash Raj Sinha (1MS24CY071) | Shreyanshu Raj (1MS24CY073)\n";
    printSeparator();
    std::cout << "  1.  Register User\n";
    std::cout << "  2.  Login\n";
    std::cout << "  3.  Access Protected Resource\n";
    std::cout << "  4.  Access Admin Resource\n";
    std::cout << "  5.  View Session Status\n";
    std::cout << "  6.  Logout\n";
    std::cout << "  7.  Logout All Sessions\n";
    std::cout << "  8.  Change Password\n";
    std::cout << "  9.  Run All 30 Security Tests\n";
    std::cout << " 10.  Exit\n";
    printSeparator();
}

// ── Session State ────────────────────────────────────────────────────────────

/**
 * Holds the current console session state.
 * This is the "client-side" — in a real app, only the token would be stored.
 */
struct ConsoleState {
    std::string currentUsername;
    std::string currentToken;
    bool loggedIn = false;
};

// ── Menu Handlers ────────────────────────────────────────────────────────────

static void handleRegister(AuthenticationManager& auth)
{
    std::cout << "\n--- Register New User ---\n";

    std::string username = readInput("Username (3-32 chars, alphanumeric/underscore): ");
    std::string password = readInput("Password (8+ chars, upper/lower/digit/special): ", true);

    // Ask for role
    std::string roleInput = readInput("Role (1=User, 2=Admin) [default: 1]: ");
    UserRole role = UserRole::USER;
    if (roleInput == "2") {
        role = UserRole::ADMIN;
    }

    if (auth.registerUser(username, password, role)) {
        std::cout << "[SUCCESS] User '" << username << "' registered as "
                  << User::roleToString(role) << ".\n";
    } else {
        std::cout << "[FAILED] Registration failed. Check username/password requirements.\n";
    }

    // Clear password from memory
    CryptoUtils::secureClear(password);
}

static void handleLogin(AuthenticationManager& auth, SessionManager& sessions,
                         ConsoleState& state)
{
    std::cout << "\n--- Login ---\n";

    if (state.loggedIn) {
        std::cout << "[INFO] Already logged in as '" << state.currentUsername
                  << "'. Logout first.\n";
        return;
    }

    std::string username = readInput("Username: ");
    std::string password = readInput("Password: ", true);

    if (auth.authenticate(username, password)) {
        // Create a new session (generates fresh token — fixation protection)
        std::string token = sessions.createSession(username);

        if (!token.empty()) {
            state.currentUsername = username;
            state.currentToken = token;
            state.loggedIn = true;

            // Show only the masked token
            std::cout << "[SUCCESS] Logged in as '" << username << "'.\n";
            std::cout << "  Token (masked): " << SecurityLogger::maskToken(token) << "\n";
            std::cout << "  (Full token stored in session — never displayed in full)\n";
        } else {
            std::cout << "[FAILED] Session creation failed (max sessions reached?).\n";
        }
    } else {
        std::cout << "[FAILED] Authentication failed. Invalid credentials, locked, or disabled.\n";
    }

    CryptoUtils::secureClear(password);
}

static void handleAccessProtected(SessionManager& sessions, ConsoleState& state)
{
    std::cout << "\n--- Access Protected Resource ---\n";

    if (!state.loggedIn) {
        std::cout << "[DENIED] Not logged in. Please login first.\n";
        return;
    }

    // Validate the session token
    const Session* session = sessions.validateToken(state.currentToken);
    if (!session) {
        std::cout << "[DENIED] Session invalid (expired, revoked, or timed out).\n";
        state.loggedIn = false;
        return;
    }

    std::cout << "[GRANTED] Access to protected resource.\n";
    std::cout << "  Welcome, " << session->getUsername() << "!\n";
    std::cout << "  Session ID: " << session->getSessionId() << "\n";
    std::cout << "  Session is valid and active.\n";
}

static void handleAccessAdmin(AuthenticationManager& auth, SessionManager& sessions,
                               ConsoleState& state)
{
    std::cout << "\n--- Access Admin Resource ---\n";

    if (!state.loggedIn) {
        std::cout << "[DENIED] Not logged in. Please login first.\n";
        return;
    }

    // Validate the session token
    const Session* session = sessions.validateToken(state.currentToken);
    if (!session) {
        std::cout << "[DENIED] Session invalid (expired, revoked, or timed out).\n";
        state.loggedIn = false;
        return;
    }

    // Check role from trusted server-side data (NOT from user input)
    const User* user = auth.getUser(session->getUsername());
    if (!user) {
        std::cout << "[ERROR] User not found in store.\n";
        return;
    }

    if (!user->isAdmin()) {
        std::cout << "[DENIED] Admin access denied. Your role: "
                  << User::roleToString(user->getRole()) << "\n";
        SecurityLogger::getInstance().logUnauthorizedAccess(
            user->getUsername(), "Admin Panel");
        return;
    }

    std::cout << "[GRANTED] Admin access granted.\n";
    std::cout << "  Welcome, Admin " << user->getUsername() << "!\n";
    std::cout << "  Admin Panel: System monitoring, user management available.\n";
    std::cout << "  Registered users: " << auth.getAllUsernames().size() << "\n";
    std::cout << "  Active sessions: " << sessions.getActiveSessionCount() << "\n";
}

static void handleViewSession(AuthenticationManager& auth, SessionManager& sessions,
                               ConsoleState& state)
{
    std::cout << "\n--- Session Status ---\n";

    if (!state.loggedIn) {
        std::cout << "[INFO] Not logged in.\n";
        return;
    }

    auto info = sessions.getSessionInfo(state.currentToken);
    if (!info.has_value()) {
        std::cout << "[INFO] Session not found or expired.\n";
        state.loggedIn = false;
        return;
    }

    const User* user = auth.getUser(info->username);

    std::cout << "  Username:       " << info->username << "\n";
    std::cout << "  Role:           " << (user ? User::roleToString(user->getRole()) : "Unknown") << "\n";
    std::cout << "  Session ID:     " << info->sessionId << "\n";
    std::cout << "  Status:         " << Session::statusToString(info->status) << "\n";
    std::cout << "  Created:        " << formatTime(info->creationTime) << "\n";
    std::cout << "  Last Activity:  " << formatTime(info->lastActivityTime) << "\n";
    std::cout << "  Expires:        " << formatTime(info->expirationTime) << "\n";

    // Show all user sessions
    auto allSessions = sessions.getUserSessions(info->username);
    std::cout << "  Total Sessions: " << allSessions.size() << "\n";
}

static void handleLogout(SessionManager& sessions, ConsoleState& state)
{
    std::cout << "\n--- Logout ---\n";

    if (!state.loggedIn) {
        std::cout << "[INFO] Not logged in.\n";
        return;
    }

    if (sessions.logout(state.currentToken)) {
        std::cout << "[SUCCESS] Logged out. Session revoked for '"
                  << state.currentUsername << "'.\n";
    } else {
        std::cout << "[INFO] Session already expired or revoked.\n";
    }

    state.loggedIn = false;
    CryptoUtils::secureClear(state.currentToken);
    state.currentUsername.clear();
}

static void handleLogoutAll(SessionManager& sessions, ConsoleState& state)
{
    std::cout << "\n--- Logout All Sessions ---\n";

    if (!state.loggedIn) {
        std::cout << "[INFO] Not logged in.\n";
        return;
    }

    int count = sessions.logoutAll(state.currentUsername);
    std::cout << "[SUCCESS] " << count << " session(s) revoked for '"
              << state.currentUsername << "'.\n";

    state.loggedIn = false;
    CryptoUtils::secureClear(state.currentToken);
    state.currentUsername.clear();
}

static void handleChangePassword(AuthenticationManager& auth, SessionManager& sessions,
                                  ConsoleState& state)
{
    std::cout << "\n--- Change Password ---\n";

    if (!state.loggedIn) {
        std::cout << "[DENIED] Not logged in. Please login first.\n";
        return;
    }

    // Validate session first
    const Session* session = sessions.validateToken(state.currentToken);
    if (!session) {
        std::cout << "[DENIED] Session expired. Please login again.\n";
        state.loggedIn = false;
        return;
    }

    std::string currentPw = readInput("Current password: ", true);
    std::string newPw = readInput("New password (8+ chars, upper/lower/digit/special): ", true);

    if (auth.changePassword(state.currentUsername, currentPw, newPw)) {
        std::cout << "[SUCCESS] Password changed for '" << state.currentUsername << "'.\n";
        std::cout << "  Note: Existing sessions remain active until logout.\n";
    } else {
        std::cout << "[FAILED] Password change failed. Check current password and new password requirements.\n";
    }

    CryptoUtils::secureClear(currentPw);
    CryptoUtils::secureClear(newPw);
}

static void handleRunTests()
{
    std::cout << "\n--- Running Security Test Suite ---\n";
    std::cout << "Executing 30 security test cases...\n";
    std::cout << "(Each test uses isolated components)\n\n";

    TestSuite suite;
    auto results = suite.runAll();
    TestSuite::printResults(results);
}

// ── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    std::cout << "============================================================\n";
    std::cout << "  SECURE SESSION MANAGEMENT WITH TOKENS\n";
    std::cout << "  24CYE551 — Secure Coding Using C/C++\n";
    std::cout << "  Yash Raj Sinha (1MS24CY071) | Shreyanshu Raj (1MS24CY073)\n";
    std::cout << "  Guide: Prof. Shankaramma | Dept: CSE (Cyber Security), MSRIT\n";
    std::cout << "============================================================\n";

    // Initialize system components with real system clock
    auto clock = std::make_shared<SystemClock>();
    AuthenticationManager auth(clock);
    SessionManager sessions(auth, clock);

    // Configure the security logger
    SecurityLogger::getInstance().setLogFile("security_log.txt");

    // Console session state
    ConsoleState state;

    // Main application loop
    bool running = true;
    while (running) {
        printMenu();

        if (state.loggedIn) {
            std::cout << "  [Logged in as: " << state.currentUsername << "]\n";
        }

        std::string choiceStr = readInput("\n  Enter choice (1-10): ");
        auto validation = InputValidator::validateMenuChoice(choiceStr, 1, 10);

        if (!validation.valid) {
            std::cout << "[ERROR] " << validation.errorMessage << "\n";
            continue;
        }

        int choice = std::stoi(choiceStr);

        switch (choice) {
        case 1:
            handleRegister(auth);
            break;
        case 2:
            handleLogin(auth, sessions, state);
            break;
        case 3:
            handleAccessProtected(sessions, state);
            break;
        case 4:
            handleAccessAdmin(auth, sessions, state);
            break;
        case 5:
            handleViewSession(auth, sessions, state);
            break;
        case 6:
            handleLogout(sessions, state);
            break;
        case 7:
            handleLogoutAll(sessions, state);
            break;
        case 8:
            handleChangePassword(auth, sessions, state);
            break;
        case 9:
            handleRunTests();
            break;
        case 10:
            // Clean logout before exit
            if (state.loggedIn) {
                sessions.logout(state.currentToken);
                CryptoUtils::secureClear(state.currentToken);
            }
            std::cout << "\n[EXIT] Goodbye. All sensitive data cleared.\n";
            running = false;
            break;
        default:
            std::cout << "[ERROR] Invalid choice.\n";
            break;
        }
    }

    return 0;
}

