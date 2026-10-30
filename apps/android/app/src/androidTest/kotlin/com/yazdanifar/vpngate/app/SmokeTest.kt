package com.yazdanifar.vpngate.app

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.printToString
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.hasText
import org.junit.Rule
import org.junit.Test

/** Launch the app, agree to the disclaimer and see the bundled server list (the APK ships VPNGate.dat). */
class SmokeTest {
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    // On a cold emulator the first frame can come late, and querying before it throws "No compose hierarchies".
    private fun eventually(timeoutMs: Long, check: () -> Boolean) {
        val end = System.currentTimeMillis() + timeoutMs
        var last: Throwable? = null
        while (System.currentTimeMillis() < end) {
            try {
                if (check()) return
            } catch (e: IllegalStateException) {
                last = e
            } catch (e: AssertionError) {
                last = e
            }
            Thread.sleep(500)
        }
        val tree = try { rule.onRoot().printToString(maxDepth = 12) } catch (e: Throwable) { "no tree: $e" }
        throw AssertionError("timed out after $timeoutMs ms; UI:\n$tree", last)
    }

    @Test
    fun launchesAndShowsTheBundledList() {
        eventually(90_000) { rule.onAllNodes(hasText("Agree and Continue")).fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("Agree and Continue").performClick()
        eventually(90_000) {
            rule.onAllNodes(hasText("Public VPN Relay Servers on the Earth!", substring = true)).fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithText("Not connected").assertExists()
    }
}
