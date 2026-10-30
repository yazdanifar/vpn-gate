package com.yazdanifar.vpngate

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.toList
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

@OptIn(ExperimentalCoroutinesApi::class)
class IpcClientTest {
    @Test
    fun repliesAreMatchedById() = runTest {
        val engine = FakeEngine()
        engine.onRequest = { cmd, _ -> if (cmd == "listServers") resultJson(listResult(server("h1", "1.1.1.1"))) else null }
        val ipc = IpcClient(engine, backgroundScope)
        val r = ipc.listServers()
        assertEquals(listOf("h1"), r.servers.map { it.hostName })
        assertEquals("1", engine.requests.single()["id"]!!.jsonPrimitive.content)
    }

    @Test
    fun failedReplyCarriesTheEngineError() = runTest {
        val engine = FakeEngine()
        engine.onRequest = { _, _ -> """"ok":false,"error":"no list"""" }
        val ipc = IpcClient(engine, backgroundScope)
        val e = assertFailsWith<EngineRequestException> { ipc.listServers() }
        assertEquals("no list", e.message)
        assertEquals(RequestFailure.Failed, e.kind)
    }

    @Test
    fun unansweredRequestTimesOut() = runTest {
        val ipc = IpcClient(FakeEngine(), backgroundScope)
        val e = assertFailsWith<EngineRequestException> { ipc.request("probe", timeoutMs = 50) }
        assertEquals(RequestFailure.Timeout, e.kind)
    }

    @Test
    fun eventsAreDecodedAndRepliesAreNotEvents() = runTest {
        val engine = FakeEngine()
        val ipc = IpcClient(engine, backgroundScope)
        val seen = mutableListOf<HelperEvent>()
        val job = launch { ipc.events.toList(seen) }
        advanceUntilIdle()
        engine.emit("""{"reply":"status","id":99,"ok":true}""")
        engine.emit("not json")
        engine.emit("""{"state":"connected","server":"1.2.3.4","virtualIP":"10.0.0.2","bytesIn":5,"bytesOut":6,"ipcVersion":9,"extra":1}""")
        advanceUntilIdle()
        job.cancel()
        assertEquals(1, seen.size)
        assertEquals(ConnectionState.Connected, seen[0].state)
        assertEquals(5, seen[0].bytesIn)
        assertEquals(9, seen[0].ipcVersion)
    }

    @Test
    fun connectUsesTheFlatLegacyFields() = runTest {
        val engine = FakeEngine()
        val ipc = IpcClient(engine, backgroundScope)
        ipc.connect(ConnectRequest(host = "1.2.3.4", port = 443, ports = listOf(443, 992), blockIPv6 = false))
        val r = engine.requests.single()
        assertEquals("connect", r["cmd"]!!.jsonPrimitive.content)
        assertEquals("1.2.3.4", r["host"]!!.jsonPrimitive.content)
        assertEquals("false", r["autoReconnect"]!!.jsonPrimitive.content)
        assertEquals("false", r["blockIPv6"]!!.jsonPrimitive.content)
        assertNull(r["proxy"])
        ipc.disconnect()
        assertEquals(listOf("connect", "disconnect"), engine.commands())
    }
}
