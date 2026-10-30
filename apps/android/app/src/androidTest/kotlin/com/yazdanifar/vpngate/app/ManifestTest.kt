package com.yazdanifar.vpngate.app

import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** What the installed package tells the system about the VPN service (always-on VPN and lockdown depend on it). */
class ManifestTest {
    @Test
    fun theServiceIsEligibleForAlwaysOnVpn() {
        val context = Harness.context
        val pm = context.packageManager
        val info = pm.getServiceInfo(ComponentName(context, VpnEngineService::class.java), PackageManager.GET_META_DATA)
        assertEquals("android.permission.BIND_VPN_SERVICE", info.permission)
        assertTrue("exported, so the system can start it", info.exported)
        assertTrue(
            "SUPPORTS_ALWAYS_ON",
            info.metaData.getBoolean("android.net.VpnService.SUPPORTS_ALWAYS_ON", false),
        )
        // The system finds the always-on service by this action.
        val resolved = pm.queryIntentServices(Intent("android.net.VpnService").setPackage(context.packageName), 0)
        assertNotNull(resolved.singleOrNull { it.serviceInfo.name == VpnEngineService::class.java.name })
    }
}
