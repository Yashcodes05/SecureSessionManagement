#pragma once

// ============================================================================
// Clock.h — Injectable clock abstraction for time-dependent features
//
// Purpose: Decouple session timeout logic from the real system clock so that
// time-dependent behaviour (token expiry, session timeout, idle detection)
// can be tested deterministically without waiting for wall-clock time.
//
// Usage:
//   Production code:  std::shared_ptr<IClock> clock = std::make_shared<SystemClock>();
//   Test code:         auto clock = std::make_shared<TestClock>();
//                      clock->advance(std::chrono::seconds(3600)); // simulate 1hr
//
// This is a header-only module — no .cpp file required.
// ============================================================================

#include <chrono>

namespace ssm {

// ============================================================================
// IClock — Abstract interface for clock providers
//
// All time-dependent components should depend on IClock, never on
// std::chrono::system_clock directly. This enables deterministic testing.
// ============================================================================
class IClock {
public:
    virtual ~IClock() = default;

    /// Return the current time point.
    virtual std::chrono::system_clock::time_point now() const = 0;
};

// ============================================================================
// SystemClock — Production clock that delegates to std::chrono::system_clock
// ============================================================================
class SystemClock : public IClock {
public:
    std::chrono::system_clock::time_point now() const override {
        return std::chrono::system_clock::now();
    }
};

// ============================================================================
// TestClock — Manually controllable clock for unit tests
//
// Initialises to the real system time at construction, then only changes
// when explicitly advanced or set. This allows tests to:
//   1. Start from a realistic baseline time
//   2. Advance time by exact amounts to test timeout boundaries
//   3. Set absolute times for edge-case testing
// ============================================================================
class TestClock : public IClock {
public:
    TestClock()
        : currentTime_(std::chrono::system_clock::now()) {}

    std::chrono::system_clock::time_point now() const override {
        return currentTime_;
    }

    /// Advance the clock by the specified duration.
    /// @param seconds  Amount of time to add to the current clock value
    void advance(std::chrono::seconds seconds) {
        currentTime_ += seconds;
    }

    /// Set the clock to an absolute time point.
    /// Useful for testing specific date/time edge cases.
    /// @param tp  The time point to set
    void setTime(std::chrono::system_clock::time_point tp) {
        currentTime_ = tp;
    }

private:
    std::chrono::system_clock::time_point currentTime_;
};

} // namespace ssm
