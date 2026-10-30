package com.yazdanifar.vpngate

/** Search, country, favourites and logging-policy filter of the server list (ServerFilter.swift). */
data class ServerFilter(
    val search: String = "",
    val country: String = ALL_COUNTRIES,
    val favoritesOnly: Boolean = false,
    /** Hide servers that keep logs longer than this many weeks (null = show all). */
    val maxLogWeeks: Int? = null,
) {
    val isActive: Boolean get() = search.isNotEmpty() || country != ALL_COUNTRIES || favoritesOnly || maxLogWeeks != null

    fun apply(servers: List<VpnServer>, favorites: Set<String>): List<VpnServer> = servers.filter { matches(it, favorites) }

    private fun matches(s: VpnServer, favorites: Set<String>): Boolean {
        if (country != ALL_COUNTRIES && s.countryLong != country) return false
        if (favoritesOnly && s.id !in favorites) return false
        if (maxLogWeeks != null) {
            // unknown retention is treated as "too long"
            val w = logWeeks(s.logType)
            if (w == null || w > maxLogWeeks) return false
        }
        if (search.isNotEmpty()) {
            fun hit(f: String) = f.contains(search, ignoreCase = true)
            if (!(hit(s.hostName) || hit(s.ip) || hit(s.countryLong) || hit(s.operatorName))) return false
        }
        return true
    }

    companion object {
        const val ALL_COUNTRIES = "All"

        /** "2weeks" → 2, "3months" → 13, "1year" → 52, "no" / "none" / "0" → 0, unparseable → null. */
        fun logWeeks(s: String): Int? {
            val t = s.lowercase().trim()
            if (t == "no" || t == "none" || t == "nolog" || t == "0") return 0
            val digits = t.takeWhile { it in '0'..'9' }
            if (digits.isEmpty()) return null
            val n = digits.toIntOrNull() ?: return null
            return when (t.substring(digits.length).trim()) {
                "day", "days" -> (n + 6) / 7
                "week", "weeks" -> n
                "month", "months" -> n * 52 / 12 + if (n * 52 % 12 == 0) 0 else 1
                "year", "years" -> n * 52
                else -> null
            }
        }
    }
}

enum class SortKey { Score, Host, Country, Uptime, Sessions, Speed, Ping, Logging, Test }

fun List<VpnServer>.sortedBy(key: SortKey, descending: Boolean, probes: Map<String, Probe> = emptyMap()): List<VpnServer> {
    val cmp: Comparator<VpnServer> = when (key) {
        SortKey.Score -> compareBy { it.score }
        SortKey.Host -> compareBy(String.CASE_INSENSITIVE_ORDER) { it.hostName }
        SortKey.Country -> compareBy(String.CASE_INSENSITIVE_ORDER) { it.countryLong }
        SortKey.Uptime -> compareBy { it.uptimeMs }
        SortKey.Sessions -> compareBy { it.sessions }
        SortKey.Speed -> compareBy { it.speed }
        // unknown ping (0) sorts as slowest
        SortKey.Ping -> compareBy { if (it.ping == 0) Int.MAX_VALUE else it.ping }
        SortKey.Logging -> compareBy { ServerFilter.logWeeks(it.logType) ?: Int.MAX_VALUE }
        SortKey.Test -> compareBy { Probe.sortRank(probes[it.id]) }
    }
    return sortedWith(if (descending) cmp.reversed() else cmp)
}
