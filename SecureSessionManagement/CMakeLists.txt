cmake_minimum_required(VERSION 3.20)

project(SecureSessionManagement
    VERSION 1.0.0
    DESCRIPTION "Secure Session Management with Tokens - 24CYE551 Secure Coding"
    LANGUAGES CXX
)

# ── C++17 Standard ──────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler-specific security hardening flags ─────────────────────────────
if(MSVC)
    # /W4   = high warning level
    # /sdl  = additional security checks (SDL)
    # /GS   = buffer security check (stack canaries)
    # /guard:cf = control-flow guard (CFG)
    add_compile_options(/W4 /sdl /GS /guard:cf)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
else()
    # GCC / Clang equivalents:
    # -Wall -Wextra: High warning diagnostics
    # -fstack-protector-strong: Stack canary protection (equivalent to /GS)
    # -D_FORTIFY_SOURCE=2: Buffer overflow detection for libc functions
    add_compile_options(-Wall -Wextra -fstack-protector-strong)
    add_compile_definitions(_FORTIFY_SOURCE=2)
endif()

# ── Include path ─────────────────────────────────────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/include)

# ── Source files ─────────────────────────────────────────────────────────────
set(LIB_SOURCES
    src/CryptoUtils.cpp
    src/InputValidator.cpp
    src/SecurityLogger.cpp
    src/User.cpp
    src/Session.cpp
    src/TokenManager.cpp
    src/AuthenticationManager.cpp
    src/SessionManager.cpp
)

# ── Static library (shared between main app and test executable) ─────────────
add_library(ssm_core STATIC ${LIB_SOURCES})
if(MSVC)
    target_link_libraries(ssm_core PUBLIC bcrypt.lib)
else()
    target_link_libraries(ssm_core PUBLIC bcrypt)
endif()

# ── Main console application ────────────────────────────────────────────────
add_executable(SecureSessionApp src/main.cpp tests/TestSuite.cpp)
target_compile_definitions(SecureSessionApp PRIVATE SSM_NO_TEST_MAIN)
target_link_libraries(SecureSessionApp PRIVATE ssm_core)

# ── Test executable ──────────────────────────────────────────────────────────
enable_testing()

add_executable(SecurityTests tests/TestSuite.cpp)
target_link_libraries(SecurityTests PRIVATE ssm_core)

add_test(
    NAME SecurityTestSuite
    COMMAND SecurityTests
)

