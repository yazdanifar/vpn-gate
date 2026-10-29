package com.yazdanifar.vpngate

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class MainModelTest {
    private val jp = server("vpn1", "1.1.1.1", "Japan", score = 10, ssl = listOf(992, 443))
    private val th = server("vpn2", "2.2.2.2", "Thailand", score = 30)

    /** The model runs in [TestScope.backgroundScope]: its event collector never ends, and runTest must not wait for it. */
    private class Rig(test: TestScope, agreed: Boolean = true, allowVpn: Boolean = true) {
        private val scope = test.backgroundScope
        val engine = FakeEngine()
        val settings = MemorySettings(hasAgreedToDisclaimer = agreed)
        var prepared = 0
        val ipc = IpcClient(engine, scope)
        val model = MainModel(
            ipc, settings, scope,
            preparer = { prepared++; allowVpn },
            clock = { test.currentTime },
            reconnectDelayMs = 15_000,
            answerTimeoutMs = 10_000,
        )
    }

    private fun TestScope.rig(agreed: Boolean = true, allowVpn: Boolean = true, fresh: Boolean = true, vararg servers: VpnServer): Rig {
        val r = Rig(this, agreed, allowVpn)
        val list = listResult(*servers, fresh = fresh)
        r.engine.onRequest = { cmd, _ ->
            when (cmd) {
                "listServers", "refreshServers" -> resultJson(list)
                else -> null
            }
        }
        return r
    }

    @Test
    fun startLoadsTheCachedListAndRefreshesWhenStale() = runTest {
        val r = rig(fresh = false, servers = arrayOf(jp, th))
        r.model.start()
        runCurrent()
        assertEquals(listOf("status", "listServers", "refreshServers"), r.engine.commands())
        assertEquals(2, r.model.state.value.allServers.size)
        assertFalse(r.model.state.value.isLoading)
        assertEquals("Cached", r.model.state.value.listSource)
    }

    @Test
    fun freshCacheIsNotRefreshed() = runTest {
        val r = rig(servers = arrayOf(jp))
        r.model.start()
        runCurrent()
        assertEquals(listOf("status", "listServers"), r.engine.commands())
    }

    @Test
    fun listFailureIsReported() = runTest {
        val r = Rig(this)
        r.engine.onRequest = { _, _ -> """"ok":false,"error":"offline"""" }
        r.model.start()
        runCurrent()
        val s = r.model.state.value
        assertEquals("offline", s.listError)
        assertEquals("List update failed (offline). Try again.", s.listStatus(0))
    }

    @Test
    fun connectBeforeConsentParksUntilAgreement() = runTest {
        val r = rig(agreed = false, servers = arrayOf(jp))
        r.model.start()
        runCurrent()
        r.model.connect(jp)
        runCurrent()
        assertTrue(r.model.state.value.showDisclaimer)
        assertFalse("connect" in r.engine.commands())

        r.model.agree()
        runCurrent()
        assertFalse(r.model.state.value.showDisclaimer)
        assertTrue(r.settings.hasAgreedToDisclaimer)
        assertTrue("connect" in r.engine.commands())
    }

    @Test
    fun connectSendsTheListedServerWithPrioritizedPorts() = runTest {
        val r = rig(servers = arrayOf(jp))
        r.model.start()
        runCurrent()
        r.model.select(jp)
        r.model.connect()
        runCurrent()
        val c = r.engine.requests.last()
        assertEquals("connect", c["cmd"]!!.jsonPrimitive.content)
        assertEquals("1.1.1.1", c["host"]!!.jsonPrimitive.content)
        assertEquals("443", c["port"]!!.jsonPrimitive.content)
        assertEquals(1, r.prepared)
        assertEquals(ConnectionState.Connecting, r.model.state.value.state)
    }

    @Test
    fun deniedVpnConsentCancelsTheConnect() = runTest {
        val r = rig(allowVpn = false, servers = arrayOf(jp))
        r.model.connect(jp)
        runCurrent()
        assertFalse("connect" in r.engine.commands())
        val s = r.model.state.value
        assertEquals(ConnectionState.Disconnected, s.state)
        assertNotNull(s.notice)
    }

    @Test
    fun eventsDriveTheState() = runTest {
        val r = rig(servers = arrayOf(jp))
        r.model.start()
        runCurrent()
        r.engine.emit("""{"state":"connected","server":"1.1.1.1","virtualIP":"10.211.0.2","bytesIn":1024,"bytesOut":5,"ipcVersion":9,"log":"hello"}""")
        runCurrent()
        val s = r.model.state.value
        assertEquals(ConnectionState.Connected, s.state)
        assertEquals("10.211.0.2", s.virtualIp)
        assertEquals("vpn1", s.serverName)
        assertEquals(listOf("hello"), s.logLines)
        assertNull(s.notice)
        assertTrue(s.trafficText(5_000).startsWith("0:00:05"))
    }

    @Test
    fun engineErrorBecomesANotice() = runTest {
        val r = rig(servers = arrayOf(jp))
        r.model.start()
        runCurrent()
        r.engine.emit("""{"state":"disconnected","bytesIn":0,"bytesOut":0,"error":"auth failed"}""")
        runCurrent()
        assertEquals("auth failed", r.model.state.value.notice)
        assertEquals("Error: auth failed", r.model.state.value.logLines.last())
    }

    @Test
    fun droppedSessionReconnectsEvery15Seconds() = runTest {
        val r = rig(servers = arrayOf(jp))
        r.model.start()
        runCurrent()
        r.model.connect(jp)
        runCurrent()
        r.engine.event("connected", "1.1.1.1")
        runCurrent()
        val connects = { r.engine.commands().count { it == "connect" } }
        assertEquals(1, connects())

        r.engine.event("disconnected")
        runCurrent()
        assertEquals(ConnectionState.Reconnecting, r.model.state.value.state)
        // the engine's own "disconnected" keeps the Reconnecting state
        r.engine.event("disconnected")
        runCurrent()
        assertEquals(ConnectionState.Reconnecting, r.model.state.value.state)

        advanceTimeBy(14_999)
        assertEquals(1, connects())
        advanceTimeBy(2)
        runCurrent()
        assertEquals(2, connects())
    }

    @Test
    fun disconnectStopsReconnecting() = runTest {
        val r = rig(servers = arrayOf(jp))
        r.model.start()
        runCurrent()
        r.model.connect(jp)
        runCurrent()
        r.engine.event("connected", "1.1.1.1")
        r.engine.event("disconnected")
        runCurrent()
        assertEquals(ConnectionState.Reconnecting, r.model.state.value.state)

        r.model.disconnect()
        runCurrent()
        assertEquals(ConnectionState.Disconnected, r.model.state.value.state)
        assertEquals("disconnect", r.engine.commands().last())
        advanceTimeBy(60_000)
        assertEquals(1, r.engine.commands().count { it == "connect" })
    }

    @Test
    fun noReconnectWhenSettingIsOff() = runTest {
        val r = rig(servers = arrayOf(jp))
        r.settings.autoReconnect = false
        r.model.start()
        runCurrent()
        r.model.connect(jp)
        runCurrent()
        r.engine.event("disconnected")
        runCurrent()
        assertEquals(ConnectionState.Disconnected, r.model.state.value.state)
    }

    @Test
    fun silentEngineTimesOutTheConnect() = runTest {
        val r = rig(servers = arrayOf(jp))
        r.model.start()
        runCurrent()
        r.model.connect(jp)
        advanceTimeBy(10_001)
        runCurrent()
        assertEquals(ConnectionState.Disconnected, r.model.state.value.state)
        assertEquals("The VPN engine is not responding.", r.model.state.value.notice)
    }

    @Test
    fun filterAndFavoritesAffectTheRows() = runTest {
        val r = rig(servers = arrayOf(jp, th))
        r.model.start()
        runCurrent()
        assertEquals(listOf("vpn2", "vpn1"), r.model.state.value.servers.map { it.hostName })
        r.model.setCountry("Japan")
        assertEquals(listOf("vpn1"), r.model.state.value.servers.map { it.hostName })
        assertTrue(r.model.state.value.listStatus(1_000).contains("showing 1"))
        r.model.clearFilters()
        r.model.toggleFavorite(th)
        assertEquals(setOf("vpn2"), r.settings.favorites)
        r.model.setFavoritesOnly(true)
        assertEquals(listOf("vpn2"), r.model.state.value.servers.map { it.hostName })
        assertEquals(listOf("Japan", "Thailand"), r.model.state.value.countries)
    }

    @Test
    fun sortingTogglesDirection() = runTest {
        val r = rig(servers = arrayOf(jp, th))
        r.model.start()
        runCurrent()
        r.model.sortBy(SortKey.Host)
        assertEquals(listOf("vpn1", "vpn2"), r.model.state.value.servers.map { it.hostName })
        r.model.sortBy(SortKey.Host)
        assertEquals(listOf("vpn2", "vpn1"), r.model.state.value.servers.map { it.hostName })
    }

    @Test
    fun staleListIsFlagged() = runTest {
        val r = rig(servers = arrayOf(jp))
        r.model.start()
        runCurrent()
        val s = r.model.state.value
        assertTrue(s.listStatus(1_000).startsWith("1 Public VPN Relay Servers on the Earth!"))
        assertTrue(s.listStatus(1_000 + 90_000_000).endsWith("The list is old — press Refresh List."))
    }
}
