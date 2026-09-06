package com.lumen.app.vm

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PingCleanupTest {
    @Test
    fun onlyCompletedResultsAtOrBelowTheThresholdAreCandidates() {
        assertTrue(isPingRemovalCandidate(0, thresholdMs = 1))
        assertTrue(isPingRemovalCandidate(1, thresholdMs = 1))
        assertFalse(isPingRemovalCandidate(2, thresholdMs = 1))
        // null means the probe was not completed; it must never be auto-removed.
        assertFalse(isPingRemovalCandidate(null, thresholdMs = 1))
    }

    @Test
    fun thresholdCanBeSetToZeroToKeepAValidOneMillisecondResult() {
        assertTrue(isPingRemovalCandidate(0, thresholdMs = 0))
        assertFalse(isPingRemovalCandidate(1, thresholdMs = 0))
    }
}
