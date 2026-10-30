package com.yazdanifar.vpngate.app

import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.core.app.ActivityOptionsCompat
import com.yazdanifar.vpngate.AccountStore
import com.yazdanifar.vpngate.AuthTypes
import com.yazdanifar.vpngate.ClientAccount
import com.yazdanifar.vpngate.ConnectionLogEntry
import com.yazdanifar.vpngate.ConnectionState
import com.yazdanifar.vpngate.EngineChannel
import com.yazdanifar.vpngate.IpcClient
import com.yazdanifar.vpngate.MainModel
import com.yazdanifar.vpngate.MemorySecretStore
import com.yazdanifar.vpngate.MemorySettings
import com.yazdanifar.vpngate.Probe
import com.yazdanifar.vpngate.ProxyKind
import com.yazdanifar.vpngate.ProxySettings
import com.yazdanifar.vpngate.RoutingAction
import com.yazdanifar.vpngate.RoutingConfig
import com.yazdanifar.vpngate.RoutingRule
import com.yazdanifar.vpngate.RoutingRuleType
import com.yazdanifar.vpngate.UiState
import com.yazdanifar.vpngate.VpnPreparer
import com.yazdanifar.vpngate.VpnServer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import java.io.File
import java.util.Locale
import java.util.TimeZone

/** Fixed data for the screenshot tests: nothing here depends on the clock, the locale or the machine. */
object Fixtures {
    init {
        // The history screen formats dates with the JVM defaults.
        Locale.setDefault(Locale.US)
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"))
    }

    private const val DAY = 86_400_000L

    val servers = listOf(
        VpnServer(
            hostName = "public-vpn-231", ip = "219.100.37.231", countryLong = "Japan", countryShort = "JP", score = 2_845_103,
            ping = 12, speed = 312_000_000, sessions = 64, uptimeMs = 41 * DAY, totalUsers = 1_204_551, totalTraffic = 9_876_543_210_000,
            logType = "2weeks", operatorName = "Tsukuba University", message = "Volunteer relay of the VPN Gate Academic Experiment Project.",
            listedPort = 1194, sslPorts = listOf(443, 992, 5555), udpPort = 1194, os = "Windows Server 2019", soft = "SoftEther VPN", build = 9680,
            owner = "Volunteer Operator", abuse = "abuse@example.org",
        ),
        VpnServer(
            hostName = "vpn-kr-42", ip = "121.140.22.42", countryLong = "Korea Republic of", countryShort = "KR", score = 1_902_330,
            ping = 38, speed = 154_000_000, sessions = 18, uptimeMs = 6 * DAY, logType = "permanent", listedPort = 1194, sslPorts = listOf(443),
        ),
        VpnServer(
            hostName = "freevpn-us-7", ip = "73.12.200.7", countryLong = "United States", countryShort = "US", score = 1_120_944,
            ping = 160, speed = 48_000_000, sessions = 5, uptimeMs = 3 * 3_600_000L, logType = "no", listedPort = 1194, sslPorts = listOf(443, 995),
        ),
        VpnServer(
            hostName = "relay-th-3", ip = "171.97.4.3", countryLong = "Thailand", countryShort = "TH", score = 640_218,
            ping = 0, speed = 9_000_000, sessions = 1, uptimeMs = 45 * 60_000L, logType = "2weeks", listedPort = 1194, sslPorts = listOf(443),
        ),
        VpnServer(
            hostName = "vpn-de-18", ip = "84.150.7.18", countryLong = "Germany", countryShort = "DE", score = 410_007,
            ping = 95, speed = 22_500_000, sessions = 9, uptimeMs = 12 * DAY, logType = "2weeks", listedPort = 1194, sslPorts = listOf(443),
        ),
    )

    val account = ClientAccount(
        id = "acct-1", name = "Office SoftEther", host = "vpn.example.com", portList = listOf(443, 5555), hub = "OFFICE",
        username = "alice", authType = AuthTypes.PASSWORD, createdAtMs = 0, updatedAtMs = 0,
    )
    val certAccount = ClientAccount(
        id = "acct-2", name = "Lab (certificate)", host = "192.0.2.10", portList = listOf(992), hub = "LAB",
        username = "bob", authType = AuthTypes.CERTIFICATE, checkServerCert = true,
        serverCertFingerprint = "AA".repeat(20), createdAtMs = 0, updatedAtMs = 0,
    )

    val history = listOf(
        ConnectionLogEntry(
            id = "h1", serverName = "public-vpn-231", serverIp = "219.100.37.231", connectedAtMs = 1_767_268_800_000,
            disconnectedAtMs = 1_767_272_700_000, durationSeconds = 3_900.0, bytesIn = 183_500_000, bytesOut = 12_400_000,
        ),
        ConnectionLogEntry(
            id = "h2", serverName = "vpn-kr-42", serverIp = "121.140.22.42", connectedAtMs = 1_767_182_400_000,
            disconnectedAtMs = 1_767_182_460_000, durationSeconds = 60.0, bytesIn = 0, bytesOut = 0, error = "Authentication failed",
        ),
        ConnectionLogEntry(id = "h3", serverName = "relay-th-3", serverIp = "171.97.4.3", connectedAtMs = 1_767_096_000_000),
    )

    val routing = RoutingConfig(
        rules = listOf(
            RoutingRule(id = "r1", type = RoutingRuleType.Cidr, value = "192.168.50.0/24", action = RoutingAction.Direct),
            RoutingRule(id = "r2", type = RoutingRuleType.Ip, value = "203.0.113.5", action = RoutingAction.Direct, enabled = false),
        ),
        bypassPrivateNetworks = true,
    )

    val base = UiState(
        allServers = servers,
        listSource = "Cached",
        listTimestampMs = null, // a timestamp would make the status line depend on today's date
        favorites = setOf(servers[1].id),
        selectedId = servers[0].id,
    )

    val connected = base.copy(
        state = ConnectionState.Connected, server = servers[0].ip, virtualIp = "10.21.0.17",
        bytesIn = 48_300_000, bytesOut = 3_100_000,
        probes = mapOf(servers[0].id to Probe.Ok(14, 22, 443), servers[2].id to Probe.Failed("timeout")),
    )

    val connecting = base.copy(state = ConnectionState.Authenticating, server = servers[0].ip)

    private class NoEngine : EngineChannel {
        override var listener: ((String) -> Unit)? = null
        override fun send(requestJson: String) {}
    }

    /** A model that never reaches an engine; the screens only call it from click handlers. */
    fun model(): MainModel {
        val dir = File(System.getProperty("java.io.tmpdir"), "vpngate-paparazzi-" + System.nanoTime()).also { it.mkdirs() }
        val store = AccountStore(File(dir, "accounts.json"), MemorySecretStore())
        store.add(account, "secret")
        store.add(certAccount)
        return MainModel(
            ipc = IpcClient(NoEngine(), CoroutineScope(Job())),
            settings = MemorySettings(hasAgreedToDisclaimer = true),
            scope = CoroutineScope(Job()),
            preparer = VpnPreparer { false },
            accountStore = store,
        )
    }

    fun proxyHttp() = ProxySettings(kind = ProxyKind.Http, host = "proxy.example.net", port = 8080, username = "carol")
}

/** The editor registers file pickers; Paparazzi has no activity, so give it a registry that never launches anything. */
@Composable
fun WithNoActivity(content: @Composable () -> Unit) {
    val owner = object : ActivityResultRegistryOwner {
        override val activityResultRegistry = object : ActivityResultRegistry() {
            override fun <I, O> onLaunch(requestCode: Int, contract: ActivityResultContract<I, O>, input: I, options: ActivityOptionsCompat?) {}
        }
    }
    CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner, content = content)
}
