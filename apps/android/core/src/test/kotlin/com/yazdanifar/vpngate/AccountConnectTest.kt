package com.yazdanifar.vpngate

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class AccountConnectTest {
    private val dir: File = Files.createTempDirectory("vpngate-model").toFile().also { it.deleteOnExit() }

    private class Rig(test: TestScope, dir: File) {
        val engine = FakeEngine()
        val settings = MemorySettings(hasAgreedToDisclaimer = true)
        val secrets = MemorySecretStore()
        val accounts = AccountStore(File(dir, "accounts.json"), secrets)
        val history = ConnectionHistoryStore(File(dir, "history.json")) { test.currentTime }
        val model = MainModel(
            IpcClient(engine, test.backgroundScope), settings, test.backgroundScope,
            preparer = { true },
            clock = { test.currentTime },
            accountStore = accounts,
            historyStore = history,
        )

        init {
            engine.onRequest = { cmd, _ -> if (cmd == "listServers" || cmd == "refreshServers") resultJson(listResult(server("vpn1", "1.1.1.1"))) else null }
        }
    }

    @Test
    fun connectingAnAccountSendsItsConfig() = runTest {
        val r = Rig(this, dir)
        r.model.start()
        r.model.saveAccount(AccountEditorState(name = "Work", host = "vpn.example.com", username = "bob", password = "pw"), null)
        val account = r.model.state.value.accounts.single()
        r.model.updateSettings(globalRouting = RoutingConfig(bypassPrivateNetworks = true))
        r.model.connectAccount(account)
        runCurrent()
        val connect = r.engine.requests.last { it["cmd"]!!.jsonPrimitive.content == "connect" }
        val cfg = connect["config"]!!.jsonObject
        assertEquals("vpn.example.com", cfg["host"]!!.jsonPrimitive.content)
        assertEquals("pw", cfg["password"]!!.jsonPrimitive.content)
        assertTrue("routing" in cfg, "global rules apply to an account without its own")
        assertEquals(account.id, r.settings.lastAccountId)
        assertEquals(null, r.settings.lastServer)
    }

    @Test
    fun aListConnectionCarriesTheProxy() = runTest {
        val r = Rig(this, dir)
        r.model.start()
        runCurrent()
        r.model.updateSettings(proxy = ProxySettings(ProxyKind.Http, "proxy.example", 3128))
        r.model.select(r.model.state.value.allServers.single())
        r.model.connect()
        runCurrent()
        val connect = r.engine.requests.last { it["cmd"]!!.jsonPrimitive.content == "connect" }
        assertEquals("proxy.example", connect["proxy"]!!.jsonObject["host"]!!.jsonPrimitive.content)
    }

    @Test
    fun historyHasOneEntryPerConnectedPeriod() = runTest {
        val r = Rig(this, dir)
        r.model.start()
        runCurrent()
        r.model.select(r.model.state.value.allServers.single())
        r.model.connect()
        runCurrent()
        r.engine.event("connected", "1.1.1.1")
        runCurrent()
        r.engine.event("connected", "1.1.1.1", extra = ""","bytesIn":1""")
        runCurrent()
        assertEquals(1, r.model.state.value.history.size)
        r.model.updateSettings(autoReconnect = false)
        r.model.disconnect()
        r.engine.event("disconnected")
        runCurrent()
        val e = r.model.state.value.history.single()
        assertEquals("vpn1", e.serverName)
        assertTrue(e.disconnectedAtMs != null)
        r.model.clearHistory()
        assertTrue(r.model.state.value.history.isEmpty())
        assertFalse(File(dir, "history.json").readText().contains("vpn1"))
    }
}
