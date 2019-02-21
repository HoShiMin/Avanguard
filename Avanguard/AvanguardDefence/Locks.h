#pragma once

class RWLock {
private:
    SRWLOCK Lock;
public:
    RWLock(const RWLock&) = delete;
    RWLock(RWLock&&) = delete;
    RWLock& operator = (const RWLock&) = delete;
    RWLock& operator = (RWLock&&) = delete;

    RWLock() : Lock(SRWLOCK_INIT) {}
    ~RWLock() = default;

    void inline LockShared() { AcquireSRWLockShared(&Lock); }
    void inline UnlockShared() { ReleaseSRWLockShared(&Lock); }
    void inline LockExclusive() { AcquireSRWLockExclusive(&Lock); }
    void inline UnlockExclusive() { ReleaseSRWLockExclusive(&Lock); }
    bool inline TryLockShared() { return TryAcquireSRWLockShared(&Lock); }
    bool inline TryLockExclusive() { return TryAcquireSRWLockExclusive(&Lock); }
};