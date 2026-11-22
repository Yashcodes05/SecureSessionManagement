# Secure Session Management — Build & Run Guide

## Prerequisites

You have **CMake** ✅ but need a **C++ compiler**. Choose one option below:

---

## Option A: Install Visual Studio 2022 Community (Recommended)

### Step 1 — Download & Install
1. Go to [https://visualstudio.microsoft.com/downloads/](https://visualstudio.microsoft.com/downloads/)
2. Download **Visual Studio 2022 Community** (free)
3. In the installer, select the workload: **"Desktop development with C++"**
4. Click Install (≈4–8 GB)

### Step 2 — Build from Developer Command Prompt

After installation, open **"Developer Command Prompt for VS 2022"** (search in Start Menu) and run:

```cmd
cd /d "E:\sec codinhg\SecureSessionManagement"

cmake -S . -B build -G "Visual Studio 17 2022" -A x64

cmake --build build --config Debug
```

### Step 3 — Run

```cmd
:: Run the main application
build\Debug\SecureSessionApp.exe

:: Run the 30 security tests
build\Debug\SecurityTests.exe

:: Or use CTest
ctest --test-dir build -C Debug --output-on-failure
```

---

## Option B: Install Build Tools Only (Smaller, ~2-3 GB)

### Step 1 — Download
1. Go to [https://visualstudio.microsoft.com/downloads/](https://visualstudio.microsoft.com/downloads/)
2. Scroll down to **"Tools for Visual Studio"** → **"Build Tools for Visual Studio 2022"**
3. In the installer, select **"Desktop development with C++"**
4. Install

### Step 2 — Build

Open **"Developer Command Prompt for VS 2022"** and run:

```cmd
cd /d "E:\sec codinhg\SecureSessionManagement"

cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Debug
```

### Step 3 — Run (same as Option A)

```cmd
build\Debug\SecureSessionApp.exe
build\Debug\SecurityTests.exe
```

---

## Option C: Open in Visual Studio 2022 (GUI)

If you install full Visual Studio 2022:

1. Open Visual Studio 2022
2. File → Open → **CMake...** → select `E:\sec codinhg\SecureSessionManagement\CMakeLists.txt`
3. Visual Studio will auto-configure the CMake project
4. Select **Debug | x64** from the toolbar
5. Set `SecureSessionApp` as the startup project
6. Press **F5** to build and run
7. To run tests: Test → Run All Tests

---

## What the Programs Do

| Executable | Description |
|---|---|
| `SecureSessionApp.exe` | Interactive console app — register users, login, access resources, logout |
| `SecurityTests.exe` | Runs all 30 automated security tests — PASS/FAIL report |

---

## Quick Verification After Building

```cmd
:: Run tests first to verify everything works
build\Debug\SecurityTests.exe

:: Then try the interactive app
build\Debug\SecureSessionApp.exe
```

Expected test output:
```
=== Secure Session Management — Security Test Suite ===
Running 30 security test cases...

================================================================
      SECURITY TEST SUITE — 30 TEST CASES
================================================================

--- A. Registration & Password Security ---
  [PASS] TC01 - Valid User Registration
  [PASS] TC02 - Duplicate Username Registration
  ... (30 tests total)
================================================================
  TOTAL: 30  |  PASSED: 30  |  FAILED: 0
================================================================

All tests PASSED.
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `cmake` not found | Open "Developer Command Prompt for VS 2022" instead of regular cmd/PowerShell |
| `bcrypt.lib` link error | Already handled by CMakeLists.txt — ensure you're using MSVC, not MinGW |
| Build errors about `<windows.h>` | Make sure "Desktop development with C++" workload is installed |
| `cl.exe` not found | Use Developer Command Prompt, not regular terminal |

