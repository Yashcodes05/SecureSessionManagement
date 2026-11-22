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

# ── MSVC-specific flags ─────────────────────────────────────────────────────
if(MSVC)
    # /W4   = high warning level
    # /WX   = treat warnings as errors (optional, remove if too strict)
    # /sdl  = additional security checks
    # /GS   = buffer security check
    # /guard:cf = control-flow guard
    add_compile_options(/W4 /sdl /GS /guard:cf)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
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

