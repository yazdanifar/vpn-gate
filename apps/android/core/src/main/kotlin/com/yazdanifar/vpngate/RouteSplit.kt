package com.yazdanifar.vpngate

/**
 * `VpnService.Builder.excludeRoute` exists from API 33. Below that the plan's excluded routes are removed from the
 * included ones by splitting them into the CIDR blocks that remain. IPv4 only: IPv6 routes pass through unchanged
 * (the plan only excludes IPv4 destinations).
 */
object RouteSplit {
    private data class Cidr(val base: Long, val prefix: Int) {
        val last: Long get() = base + (1L shl (32 - prefix)) - 1
        fun contains(o: Cidr) = base <= o.base && o.last <= last
        fun overlaps(o: Cidr) = base <= o.last && o.base <= last
        override fun toString(): String = "${(base shr 24) and 255}.${(base shr 16) and 255}.${(base shr 8) and 255}.${base and 255}/$prefix"
    }

    private fun parse(s: String): Cidr? {
        val (addr, len) = s.split("/").let { if (it.size == 2) it[0] to it[1] else return null }
        val prefix = len.toIntOrNull()?.takeIf { it in 0..32 } ?: return null
        val octets = addr.split(".")
        if (octets.size != 4) return null
        var v = 0L
        for (o in octets) v = (v shl 8) or (o.toIntOrNull()?.takeIf { it in 0..255 }?.toLong() ?: return null)
        val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        return Cidr(v and mask, prefix)
    }

    private fun subtract(route: Cidr, hole: Cidr): List<Cidr> {
        if (!route.overlaps(hole)) return listOf(route)
        if (hole.contains(route)) return emptyList()
        // the hole is strictly inside: keep the half that does not contain it, recurse into the other
        val half = Cidr(route.base, route.prefix + 1)
        val other = Cidr(route.base + (1L shl (32 - half.prefix)), half.prefix)
        return if (half.overlaps(hole)) listOf(other) + subtract(half, hole) else listOf(half) + subtract(other, hole)
    }

    fun split(routes: List<String>, excluded: List<String>): List<String> {
        val holes = excluded.mapNotNull(::parse)
        val out = mutableListOf<String>()
        for (r in routes) {
            val c = parse(r)
            if (c == null) {
                out += r
                continue
            }
            var parts = listOf(c)
            for (h in holes) parts = parts.flatMap { subtract(it, h) }
            out += parts.sortedBy { it.base }.map { it.toString() }
        }
        return out
    }
}
