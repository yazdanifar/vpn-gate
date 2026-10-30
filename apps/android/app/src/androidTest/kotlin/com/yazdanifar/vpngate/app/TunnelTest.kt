package com.yazdanifar.vpngate.app

import android.Manifest
import android.content.Intent
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.rule.GrantPermissionRule
import com.yazdanifar.vpngate.ConnectionState
import com.yazdanifar.vpngate.app.Harness.eventually
import com.yazdanifar.vpngate.app.Harness.waitFor
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Connects to the SoftEther container on the CI runner through the app's own screens and checks that traffic really
 * leaves through it. The runner's web server answers with the address it sees: the emulator's own address without the
 * tunnel, the container's SecureNAT address with it.
 */
class TunnelTest {
    @get:Rule(order = 0)
    val permission: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS)

    @get:Rule(order = 1)
    val compose = createEmptyComposeRule()

    private var session: Harness.Session? = null
    private lateinit var url: String
    private lateinit var direct: String

    @Before
    fun setUp() {
        url = Harness.webUrl ?: run {
            assumeTrue("no -e hermeticWeb: the SoftEther container is not available", false)
            ""
        }
        Harness.resetAppState()
        Harness.addServerAccount()
        direct = Harness.fetchEventually(url)
    }

    @After
    fun tearDown() {
        session?.close()
        if (Harness.webUrl != null) Harness.stopTunnel()
    }

    private fun connectFromTheAccountsScreen() {
        eventually(30_000, "the main screen") { compose.onAllNodes(hasText("Menu")).fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithText("Menu").performClick()
        compose.onNodeWithText("Connection settings").performClick()
        compose.onNodeWithText("Connect").performClick()
        Harness.acceptConsentIfNeeded()
    }

    private fun assertThroughSecureNat(label: String) {
        val seen = Harness.fetchEventually(url, 60_000)
        assertNotEquals("$label: the web server saw the same address as without the tunnel ($direct)", direct, seen)
        assertTrue("$label: expected the container's address on the docker bridge, got $seen", seen.startsWith("172."))
    }

    @Test
    fun connectsAndSendsTrafficThroughSecureNat() {
        session = Harness.launchApp()
        val s = session!!
        connectFromTheAccountsScreen()
        s.waitFor(ConnectionState.Connected, 120_000)
        assertNotNull("a virtual address from SecureNAT's DHCP", s.state.virtualIp)
        compose.onNodeWithText("Disconnect").assertExists()
        assertNotNull("the foreground notification while connected", Harness.vpnNotification())
        assertThroughSecureNat("connected")

        s.model.disconnect()
        s.waitFor(ConnectionState.Disconnected, 30_000)
        eventually(30_000, "traffic to be direct again") { Harness.fetch(url) == direct }
    }

    /**
     * The system starts an always-on VPN service with the `android.net.VpnService` action and no extras (and restarts a
     * killed sticky service with a null intent): the service must replay the last connect request on its own.
     */
    @Test
    fun theSystemsAlwaysOnStartReconnectsToTheLastServer() {
        session = Harness.launchApp()
        val s = session!!
        connectFromTheAccountsScreen()
        s.waitFor(ConnectionState.Connected, 120_000)

        // Stop everything the way a process death would leave it: no tunnel, no service. The last request stays saved.
        s.model.disconnect()
        s.waitFor(ConnectionState.Disconnected, 30_000)
        Harness.context.stopService(Intent(Harness.context, VpnEngineService::class.java))
        eventually(20_000, "the service to stop") { VpnBridge.service == null }
        assertNotNull("the last account is remembered", AppSettings(Harness.context, Harness.app.secrets).lastAccountId)

        Harness.context.startForegroundService(Intent(Harness.context, VpnEngineService::class.java).setAction(Harness.ALWAYS_ON_ACTION))

        // No tap on the screen: the connection comes back by itself.
        s.waitFor(ConnectionState.Connected, 120_000)
        assertNotNull(Harness.vpnNotification())
        assertThroughSecureNat("after the always-on start")
    }

    /** `adb shell cmd connectivity airplane-mode`: the radios go away, the tunnel drops, and it comes back. */
    @Test
    fun reconnectsAfterAirplaneModeIsToggled() {
        session = Harness.launchApp()
        val s = session!!
        connectFromTheAccountsScreen()
        s.waitFor(ConnectionState.Connected, 120_000)
        assertThroughSecureNat("before airplane mode")

        val states = mutableListOf<ConnectionState>()
        val watcher = Thread {
            try {
                while (true) {
                    val now = s.state.state
                    if (states.lastOrNull() != now) synchronized(states) { states += now }
                    Thread.sleep(200)
                }
            } catch (_: InterruptedException) {
            }
        }.also { it.start() }
        try {
            airplane(true)
            // Long enough for the keep-alive to notice (SoftEther's is about 15 s).
            Thread.sleep(25_000)
            airplane(false)
            eventually(150_000, "the tunnel to come back (states: ${synchronized(states) { states.toList() }})") {
                synchronized(states) { states.any { it != ConnectionState.Connected } } && s.state.state == ConnectionState.Connected
            }
        } finally {
            watcher.interrupt()
            airplane(false)
        }
        assertThroughSecureNat("after airplane mode (states: ${synchronized(states) { states.toList() }})")
    }

    private fun airplane(on: Boolean) {
        val word = if (on) "enable" else "disable"
        val out = Harness.shell("cmd connectivity airplane-mode $word")
        if (out.contains("rror") || out.contains("nknown")) {
            Harness.shell("settings put global airplane_mode_on ${if (on) 1 else 0}")
            Harness.shell("am broadcast -a android.intent.action.AIRPLANE_MODE --ez state $on")
        }
        // Give the radios time to follow.
        Thread.sleep(2_000)
        assertEquals(if (on) "1" else "0", Harness.shell("settings get global airplane_mode_on").trim())
    }
}
