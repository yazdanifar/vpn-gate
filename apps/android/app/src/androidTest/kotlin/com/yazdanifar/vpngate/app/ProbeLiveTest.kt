package com.yazdanifar.vpngate.app

import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import com.yazdanifar.vpngate.IpcClient
import com.yazdanifar.vpngate.MainModel
import com.yazdanifar.vpngate.ProbeTarget
import com.yazdanifar.vpngate.ServerListResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * "Test Connection" against real VPN Gate relays from the emulator, through the same path as the app: the Kotlin
 * [IpcClient] over the in-process UniFFI engine, 8 relays per `probe` request, the relay's ports in priority order.
 * Needs the internet, so it runs only with `-e liveRelays true` (the Test Connection workflow); otherwise skipped.
 * The table goes to logcat (tag ProbeLive) and to the instrumentation status, so the job log shows it.
 */
class ProbeLiveTest {
    private val args get() = InstrumentationRegistry.getArguments()

    private fun report(line: String) {
        Log.i("ProbeLive", line)
        val b = android.os.Bundle()
        b.putString("stream", line + "\n")
        Harness.instrumentation.sendStatus(0, b)
    }

    @Test
    fun testConnectionReachesRealRelays() = runBlocking {
        assumeTrue("needs -e liveRelays true", args.getString("liveRelays") == "true")
        val count = args.getString("liveCount")?.toIntOrNull() ?: 24
        Harness.resetAppState()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val ipc = IpcClient(Harness.app.hub, scope)
            val list: ServerListResult = withTimeoutOrNull(150_000) { runCatching { ipc.refreshServers() }.getOrNull() }
                ?: ipc.listServers()
            report("list: ${list.servers.size} servers, source ${list.source}, fresh ${list.isFresh}, outcome ${list.outcome}")
            val servers = list.servers.filter { it.sslPorts.isNotEmpty() }.sortedByDescending { it.score }.take(count)
            assertTrue("no relay with an SSL port in the list", servers.isNotEmpty())

            val started = System.currentTimeMillis()
            var ok = 0
            val implausible = mutableListOf<String>()
            for (batch in servers.chunked(MainModel.PROBE_BATCH)) {
                val r = ipc.probe(batch.map { ProbeTarget(it.ip, it.prioritizedSslPorts.takeIf { p -> p.isNotEmpty() }) })
                assertEquals("one result per target", batch.size, r.results.size)
                for ((s, e) in batch.zip(r.results)) {
                    assertEquals("results keep the order of the request", s.ip, e.host)
                    if (e.ok) {
                        ok++
                        val c = e.connectMs ?: 0
                        val h = e.helloMs ?: 0
                        if (c !in 1..60_000 || h < c || e.port == null) implausible += "${s.ip}: connect $c, hello $h, port ${e.port}"
                        report(String.format("%-16s %-20s %6d ms :%d build %s", s.ip, s.prioritizedSslPorts, c, e.port, e.build))
                    } else {
                        if (e.error.isNullOrEmpty()) implausible += "${s.ip}: failed without a reason"
                        report(String.format("%-16s %-20s FAIL %s", s.ip, s.prioritizedSslPorts, e.error))
                    }
                }
            }
            report("android: $ok of ${servers.size} ok in ${(System.currentTimeMillis() - started) / 1000} s")
            assertTrue("implausible results: $implausible", implausible.isEmpty())
            assertTrue("Test Connection found no working relay on Android", ok >= 1)
        } finally {
            scope.cancel()
        }
    }
}
