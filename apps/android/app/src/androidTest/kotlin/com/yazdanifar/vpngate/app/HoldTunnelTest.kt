package com.yazdanifar.vpngate.app

import android.Manifest
import androidx.test.rule.GrantPermissionRule
import com.yazdanifar.vpngate.app.Harness.waitFor
import com.yazdanifar.vpngate.ConnectionState
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * Not a test of its own: scripts/ci-android-emulator.sh runs it in the background to get a connected tunnel in an
 * app process it can then kill -9, to watch the system restart the sticky VPN service. Skipped without the server.
 */
class HoldTunnelTest {
    @get:Rule
    val permission: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS)

    @Test
    fun connectAndHold() {
        assumeTrue("no -e hermeticWeb", Harness.webUrl != null)
        Harness.resetAppState()
        val account = Harness.addServerAccount()
        val s = Harness.launchApp()
        Harness.acceptConsentIfNeeded()
        s.model.connectAccount(account)
        s.waitFor(ConnectionState.Connected, 120_000)
        Thread.sleep(240_000)
    }
}
