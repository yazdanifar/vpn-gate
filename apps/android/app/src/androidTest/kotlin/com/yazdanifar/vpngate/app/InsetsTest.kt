package com.yazdanifar.vpngate.app

import android.Manifest
import android.provider.Settings
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.core.view.WindowInsetsCompat
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNotNull
import org.junit.Rule
import org.junit.Test
import java.io.File

/**
 * The main screen must not run under the system bars: the title is below the status bar and the footer above the
 * navigation bar. CI runs it once per navigation mode (`-e navMode threebutton|gestural`, switched by
 * scripts/ci-android-emulator.sh) and pulls the screenshot it saves; without the argument it is skipped.
 */
class InsetsTest {
    @get:Rule(order = 0)
    val permission: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS)

    @get:Rule(order = 1)
    val rule = createAndroidComposeRule<MainActivity>()

    @Test
    fun mainScreenStaysClearOfTheSystemBars() {
        val mode = InstrumentationRegistry.getArguments().getString("navMode")
        assumeNotNull(mode)
        val expected = if (mode == "gestural") 2 else 0   // Settings.Secure navigation_mode: 0 = 3 buttons, 2 = gestures
        val actual = Settings.Secure.getInt(Harness.context.contentResolver, "navigation_mode", -1)
        assertEquals("the emulator is not in the $mode navigation mode", expected, actual)

        Harness.eventually(90_000, "the disclaimer or the list") {
            rule.onAllNodes(hasText("Agree and Continue")).fetchSemanticsNodes().isNotEmpty() ||
                rule.onAllNodes(hasText("Public VPN Relay Servers on the Earth!", substring = true)).fetchSemanticsNodes().isNotEmpty()
        }
        if (rule.onAllNodes(hasText("Agree and Continue")).fetchSemanticsNodes().isNotEmpty()) {
            rule.onNodeWithText("Agree and Continue").performClick()
        }
        Harness.eventually(90_000, "the server list") {
            rule.onAllNodes(hasText("Public VPN Relay Servers on the Earth!", substring = true)).fetchSemanticsNodes().isNotEmpty()
        }
        rule.waitForIdle()

        var bars = androidx.core.graphics.Insets.NONE
        var visible = androidx.core.graphics.Insets.NONE
        var screenHeight = 0
        rule.runOnUiThread {
            val decor = rule.activity.window.decorView
            val insets = WindowInsetsCompat.toWindowInsetsCompat(decor.rootWindowInsets)
            visible = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            bars = insets.getInsetsIgnoringVisibility(WindowInsetsCompat.Type.systemBars())
            screenHeight = decor.height
        }
        val title = rule.onNodeWithText("VPN Gate").fetchSemanticsNode().boundsInWindow
        val footer = rule.onNodeWithText("Academic project", substring = true).fetchSemanticsNode().boundsInWindow

        val dir = File(Harness.context.getExternalFilesDir(null), "insets").apply { mkdirs() }
        Harness.device.takeScreenshot(File(dir, "main-$mode.png"))

        assertTrue("no status bar inset: the test would prove nothing", bars.top > 0)
        assertTrue("no navigation bar inset in $mode mode (visible $visible, ignoring visibility $bars): the test would prove nothing", bars.bottom > 0)
        assertTrue("title (top ${title.top}) is under the status bar (${bars.top} px)", title.top >= bars.top)
        assertTrue(
            "footer (bottom ${footer.bottom}) is under the navigation bar (starts at ${screenHeight - bars.bottom})",
            footer.bottom <= screenHeight - bars.bottom,
        )
    }
}
