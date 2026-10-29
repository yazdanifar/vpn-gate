package com.yazdanifar.vpngate

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class FilterTest {
    private val jp = server("vpn1", "1.1.1.1", "Japan", score = 10, logType = "2weeks")
    private val th = server("vpn2", "2.2.2.2", "Thailand", score = 30, logType = "none")
    private val kr = server("vpn3", "3.3.3.3", "Korea", score = 20, logType = "1year")
    private val all = listOf(jp, th, kr)

    @Test
    fun searchMatchesHostIpCountryOperator() {
        assertEquals(listOf(th), ServerFilter(search = "THAI").apply(all, emptySet()))
        assertEquals(listOf(kr), ServerFilter(search = "3.3.3").apply(all, emptySet()))
        assertEquals(listOf(jp), ServerFilter(search = "vpn1").apply(all, emptySet()))
    }

    @Test
    fun countryFavoritesAndLogging() {
        assertEquals(listOf(kr), ServerFilter(country = "Korea").apply(all, emptySet()))
        assertEquals(listOf(jp), ServerFilter(favoritesOnly = true).apply(all, setOf("vpn1")))
        assertEquals(listOf(jp, th), ServerFilter(maxLogWeeks = 2).apply(all, emptySet()))
        assertEquals(listOf(th), ServerFilter(maxLogWeeks = 0).apply(all, emptySet()))
    }

    @Test
    fun logWeeks() {
        assertEquals(0, ServerFilter.logWeeks("no"))
        assertEquals(2, ServerFilter.logWeeks("2weeks"))
        assertEquals(1, ServerFilter.logWeeks("7days"))
        assertEquals(2, ServerFilter.logWeeks("2 weeks"))
        assertEquals(13, ServerFilter.logWeeks("3months"))
        assertEquals(52, ServerFilter.logWeeks("1year"))
        assertNull(ServerFilter.logWeeks("forever"))
    }

    @Test
    fun sorting() {
        assertEquals(listOf(th, kr, jp), all.sortedBy(SortKey.Score, true))
        assertEquals(listOf(jp, th, kr), all.sortedBy(SortKey.Host, false))
        assertEquals(listOf(th, jp, kr), all.sortedBy(SortKey.Logging, false))
    }
}
