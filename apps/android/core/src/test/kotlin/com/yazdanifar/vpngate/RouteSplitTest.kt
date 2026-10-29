package com.yazdanifar.vpngate

import kotlin.test.Test
import kotlin.test.assertEquals

class RouteSplitTest {
    @Test
    fun noHolesLeavesRoutesAlone() {
        assertEquals(listOf("0.0.0.0/0", "::/0"), RouteSplit.split(listOf("0.0.0.0/0", "::/0"), emptyList()))
    }

    @Test
    fun excludedHostSplitsTheDefaultRoute() {
        val r = RouteSplit.split(listOf("0.0.0.0/0"), listOf("128.0.0.0/1"))
        assertEquals(listOf("0.0.0.0/1"), r)
        val s = RouteSplit.split(listOf("10.0.0.0/8"), listOf("10.1.0.0/16"))
        // 10.0.0.0/8 minus 10.1.0.0/16 covers 2^24 - 2^16 addresses, in 8 blocks
        assertEquals(8, s.size)
        assertEquals("10.0.0.0/16", s.first())
    }

    @Test
    fun containedRouteIsDropped() {
        assertEquals(emptyList(), RouteSplit.split(listOf("192.168.1.0/24"), listOf("192.168.0.0/16")))
    }

    @Test
    fun disjointRouteIsKept() {
        assertEquals(listOf("172.16.0.0/12"), RouteSplit.split(listOf("172.16.0.0/12"), listOf("10.0.0.0/8")))
    }

    @Test
    fun addressCoverageIsExact() {
        val r = RouteSplit.split(listOf("0.0.0.0/0"), listOf("10.0.0.0/8", "192.168.0.0/16", "1.2.3.4/32"))
        fun size(c: String) = 1L shl (32 - c.substringAfter('/').toInt())
        assertEquals((1L shl 32) - (1L shl 24) - (1L shl 16) - 1, r.sumOf(::size))
    }
}
