package com.yazdanifar.vpngate.app

import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test

/** Launch the app, agree to the disclaimer and see the bundled server list (the APK ships VPNGate.dat). */
@OptIn(ExperimentalTestApi::class)
class SmokeTest {
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @Test
    fun launchesAndShowsTheBundledList() {
        rule.waitUntilExactlyOneExists(hasText("Agree and Continue"), 30_000)
        rule.onNodeWithText("Agree and Continue").performClick()
        rule.waitUntilAtLeastOneExists(hasText("Public VPN Relay Servers on the Earth!", substring = true), 60_000)
        rule.onNodeWithText("Not connected").assertExists()
    }
}
