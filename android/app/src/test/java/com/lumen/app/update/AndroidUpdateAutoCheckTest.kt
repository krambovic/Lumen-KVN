package com.lumen.app.update

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidUpdateAutoCheckTest {
    @Test
    fun autoCheckIsDueOnFirstLaunchAndAfterOneDay() {
        assertTrue(AndroidUpdateChecker.isAutoCheckDue(nowMs = 1_000L, lastCheckMs = 0L))
        assertTrue(
            AndroidUpdateChecker.isAutoCheckDue(
                nowMs = AndroidUpdateChecker.AUTO_CHECK_INTERVAL_MS,
                lastCheckMs = 0L
            )
        )
        assertTrue(
            AndroidUpdateChecker.isAutoCheckDue(
                nowMs = AndroidUpdateChecker.AUTO_CHECK_INTERVAL_MS + 1L,
                lastCheckMs = 1L
            )
        )
    }

    @Test
    fun autoCheckIsNotDueBeforeTheInterval() {
        assertFalse(
            AndroidUpdateChecker.isAutoCheckDue(
                nowMs = AndroidUpdateChecker.AUTO_CHECK_INTERVAL_MS - 1L,
                lastCheckMs = 1L
            )
        )
    }
}
