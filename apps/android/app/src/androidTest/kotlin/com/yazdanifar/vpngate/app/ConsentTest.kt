package com.yazdanifar.vpngate.app

import android.Manifest
import android.app.Notification
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.rule.GrantPermissionRule
import com.yazdanifar.vpngate.app.Harness.eventually
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * The system VPN consent dialog, driven through the real screens (Menu, Connection settings, Connect) and UiAutomator.
 * Needs no server: the consent and the foreground notification come before the first packet.
 */
class ConsentTest {
    @get:Rule(order = 0)
    val permission: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS)

    @get:Rule(order = 1)
    val compose = createEmptyComposeRule()

    private var session: Harness.Session? = null

    @Before
    fun setUp() {
        Harness.resetAppState()
        Harness.addServerAccount()
    }

    @After
    fun tearDown() {
        session?.close()
        Harness.stopTunnel()
    }

    private fun connectFromTheAccountsScreen() {
        eventually(30_000, "the main screen") { compose.onAllNodes(hasText("Menu")).fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithText("Menu").performClick()
        compose.onNodeWithText("Connection settings").performClick()
        compose.onNodeWithText("CI SoftEther").assertExists()
        compose.onNodeWithText("Connect").performClick()
    }

    @Test
    fun denyingTheConsentLeavesTheAppDisconnectedThenAllowingStartsTheService() {
        assertTrue("the emulator is fresh, so the app has no VPN consent yet", Harness.consentPending())
        session = Harness.launchApp()

        // Cancel: the app says so, nothing runs, the consent is still pending.
        connectFromTheAccountsScreen()
        Harness.answerConsent(accept = false)
        eventually(15_000, "the denial notice") {
            compose.onAllNodes(hasText("VPN permission was not granted", substring = true)).fetchSemanticsNodes().isNotEmpty()
        }
        assertTrue(Harness.consentPending())
        assertNull("no foreground notification without consent", Harness.vpnNotification())
        assertNull(VpnBridge.service)

        // OK: VpnService.prepare() now reports the consent as given and the service shows its notification.
        connectFromTheAccountsScreen()
        Harness.answerConsent(accept = true)
        eventually(15_000, "VpnService.prepare() to return null") { !Harness.consentPending() }
        eventually(30_000, "the foreground notification") { Harness.vpnNotification() != null }
        val n = Harness.vpnNotification()!!
        assertEquals("vpn", n.notification.channelId)
        assertEquals(Harness.context.getString(R.string.notification_title), n.notification.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString())
        assertTrue("ongoing", n.notification.flags and Notification.FLAG_ONGOING_EVENT != 0)
        assertEquals("the Disconnect action", "Disconnect", n.notification.actions.single().title.toString())
        assertNotNull(VpnBridge.service)
    }
}
