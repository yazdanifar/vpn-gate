package com.yazdanifar.vpngate

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ModelsTest {
    @Test
    fun portPriorityFollowsTheWindowsClient() {
        val s = VpnServer(sslPorts = listOf(1194, 22, 995, 443, 5555))
        assertEquals(listOf(443, 995, 22, 1194, 5555), s.prioritizedSslPorts)
        assertEquals(443, s.connectPort)
    }

    @Test
    fun connectPortFallsBackToTheListedPort() {
        assertEquals(1596, VpnServer(listedPort = 1596).connectPort)
        assertNull(VpnServer(listedPort = 0).connectPort)
    }

    @Test
    fun flagIsTheRegionalIndicatorPair() {
        assertEquals("🇯🇵", VpnServer(countryShort = "jp").flag)
        assertEquals("", VpnServer(countryShort = "J").flag)
    }

    @Test
    fun formatting() {
        assertEquals("0 bytes", Fmt.bytes(0))
        assertEquals("1 byte", Fmt.bytes(1))
        assertEquals("1.5 KB", Fmt.bytes(1536))
        assertEquals("12 MB", Fmt.bytes(12L * 1024 * 1024))
        assertEquals("1:02:03", Fmt.duration(3723))
        assertEquals("12.3 Mbps", Fmt.speed(12_345_678))
        assertEquals("↓ 1.0 KB  ↑ 2 bytes", Fmt.traffic(1024, 2))
        assertEquals("5 mins", ListFormat.uptime(300_000))
        assertEquals("1 hour", ListFormat.uptime(3_700_000))
        assertEquals("2 days", ListFormat.uptime(2 * 86_400_000L))
        assertEquals("No Logs", ListFormat.logging("none"))
        assertEquals("2 Weeks", ListFormat.logging("2weeks"))
        assertEquals("-", ListFormat.logging(""))
    }
}
