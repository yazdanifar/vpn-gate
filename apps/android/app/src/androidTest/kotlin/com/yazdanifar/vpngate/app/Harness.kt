package com.yazdanifar.vpngate.app

import android.app.Instrumentation
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.service.notification.StatusBarNotification
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import com.yazdanifar.vpngate.AuthTypes
import com.yazdanifar.vpngate.ClientAccount
import com.yazdanifar.vpngate.ConnectionState
import com.yazdanifar.vpngate.MainModel
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.util.regex.Pattern

/**
 * What the emulator tests share. The hermetic server is the official SoftEther container that the CI job starts on the
 * runner (scripts/ci-android-emulator.sh); the emulator reaches the runner at 10.0.2.2. The job passes
 * `-e hermeticWeb <url>` (a tiny web server on the runner that answers with the caller's address); without it the
 * tests that need the server are skipped, so a plain `connectedDebugAndroidTest` on a laptop still works.
 */
object Harness {
    const val VPN_DIALOGS = "com.android.vpndialogs"
    const val NOTIFICATION_ID = 1
    const val ALWAYS_ON_ACTION = "android.net.VpnService"

    val instrumentation: Instrumentation get() = InstrumentationRegistry.getInstrumentation()
    val context: Context get() = instrumentation.targetContext
    val device: UiDevice get() = UiDevice.getInstance(instrumentation)
    val app: VpnGateApp get() = context.applicationContext as VpnGateApp

    private val args get() = InstrumentationRegistry.getArguments()
    val serverHost: String get() = args.getString("hermeticServer") ?: "10.0.2.2"
    val webUrl: String? get() = args.getString("hermeticWeb")

    fun eventually(timeoutMs: Long, what: String, check: () -> Boolean) {
        val end = System.currentTimeMillis() + timeoutMs
        var last: Throwable? = null
        while (System.currentTimeMillis() < end) {
            try {
                if (check()) return
                last = null
            } catch (e: Exception) {
                last = e
            } catch (e: AssertionError) {
                last = e
            }
            Thread.sleep(250)
        }
        throw AssertionError("timed out after $timeoutMs ms waiting for $what", last)
    }

    /** A clean app: nothing saved, the disclaimer already agreed, no tunnel. */
    fun resetAppState() {
        stopTunnel()
        val settings = AppSettings(context, app.secrets)
        settings.hasAgreedToDisclaimer = true
        settings.lastAccountId = null
        settings.lastServer = null
        app.accounts.accounts.forEach(app.accounts::delete)
    }

    /** The connection setting for the hermetic server: hub VPNGATE, anonymous user "vpn" (scripts/test-tunnel-netns.sh). */
    fun addServerAccount(): ClientAccount {
        val account = ClientAccount(
            name = "CI SoftEther", host = serverHost, portList = listOf(443), hub = "VPNGATE", username = "vpn",
            authType = AuthTypes.ANONYMOUS, autoReconnect = true, reconnectInterval = 3.0, reconnectCount = 20,
        )
        app.accounts.add(account)
        return account
    }

    /** Disconnect the engine and stop the service, leaving no VPN behind for the next test. */
    fun stopTunnel() {
        app.hub.send("""{"cmd":"disconnect"}""")
        context.stopService(Intent(context, VpnEngineService::class.java))
        eventually(20_000, "the VPN service to stop") { VpnBridge.service == null }
    }

    fun consentPending(): Boolean = VpnService.prepare(context) != null

    /** Answer the system's "Connection request" dialog (another app's window, so Compose tests cannot reach it). */
    fun answerConsent(accept: Boolean) {
        check(device.wait(Until.hasObject(By.pkg(VPN_DIALOGS)), 30_000)) { "no VPN consent dialog appeared; screen:\n${dump()}" }
        val byId = if (accept) "android:id/button1" else "android:id/button2"
        val label = Pattern.compile(if (accept) "OK" else "Cancel", Pattern.CASE_INSENSITIVE)
        val button = device.findObject(By.pkg(VPN_DIALOGS).res(byId)) ?: device.findObject(By.pkg(VPN_DIALOGS).text(label))
        checkNotNull(button) { "no ${if (accept) "OK" else "Cancel"} button in the VPN consent dialog; screen:\n${dump()}" }
        button.click()
        check(device.wait(Until.gone(By.pkg(VPN_DIALOGS)), 15_000)) { "the VPN consent dialog stayed open" }
    }

    fun acceptConsentIfNeeded() {
        if (consentPending()) answerConsent(true)
    }

    fun dump(): String = java.io.ByteArrayOutputStream().also { device.dumpWindowHierarchy(it) }.toString("UTF-8")

    fun vpnNotification(): StatusBarNotification? =
        context.getSystemService(NotificationManager::class.java).activeNotifications.firstOrNull { it.id == NOTIFICATION_ID }

    fun shell(command: String): String = device.executeShellCommand(command)

    /**
     * One HTTP/1.0 GET over a raw socket (a plain-text HttpURLConnection is refused for apps targeting API 28+). The web
     * server on the runner answers with the address it saw, so the answer shows which path the request took.
     */
    fun fetch(url: String): String {
        val u = URI(url)
        Socket().use { s ->
            s.connect(InetSocketAddress(u.host, if (u.port > 0) u.port else 80), 5_000)
            s.soTimeout = 5_000
            s.getOutputStream().write("GET ${u.rawPath.ifEmpty { "/" }} HTTP/1.0\r\nHost: ${u.host}\r\n\r\n".toByteArray())
            val reply = s.getInputStream().readBytes().toString(Charsets.UTF_8)
            check(reply.startsWith("HTTP/1.")) { "not an HTTP reply: $reply" }
            return reply.substringAfter("\r\n\r\n").trim()
        }
    }

    fun fetchEventually(url: String, timeoutMs: Long = 30_000): String {
        var answer = ""
        eventually(timeoutMs, "an answer from $url") {
            answer = fetch(url)
            true
        }
        return answer
    }

    /** The app's activity and its view model, for tests that read the state the screens are drawn from. */
    class Session(private val scenario: ActivityScenario<MainActivity>, val model: MainModel) {
        val state get() = model.state.value
        fun close() = scenario.close()
    }

    fun launchApp(): Session {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        lateinit var model: MainModel
        scenario.onActivity { model = ViewModelProvider(it)[MainViewModel::class.java].model }
        return Session(scenario, model)
    }

    fun Session.waitFor(state: ConnectionState, timeoutMs: Long) =
        eventually(timeoutMs, "state $state (now ${this.state.state}; log: ${this.state.logLines.takeLast(6)})") { this.state.state == state }
}
