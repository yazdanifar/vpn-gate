package com.yazdanifar.vpngate

import java.util.Locale

/** Text of the UI, following UI-SPEC.md section 0 and Sources/VPNGateMac/UI/Formatting.swift. */
object Fmt {
    fun speed(bitsPerSecond: Long): String = String.format(Locale.ROOT, "%.1f Mbps", bitsPerSecond / 1_000_000.0)

    /** Binary units like ByteCountFormatter: "0 bytes", "12 bytes", "1.5 KB", "3.2 MB". */
    fun bytes(n: Long): String {
        if (n < 1024) return if (n == 1L) "1 byte" else "$n bytes"
        val units = listOf("KB", "MB", "GB", "TB", "PB")
        var v = n.toDouble()
        var i = -1
        do {
            v /= 1024
            i++
        } while (v >= 1024 && i < units.size - 1)
        val s = if (v < 10) String.format(Locale.ROOT, "%.1f", v) else String.format(Locale.ROOT, "%.0f", v)
        return "$s ${units[i]}"
    }

    fun duration(seconds: Long): String {
        val s = maxOf(0, seconds)
        return String.format(Locale.ROOT, "%d:%02d:%02d", s / 3600, s % 3600 / 60, s % 60)
    }

    fun title(s: ConnectionState): String = when (s) {
        ConnectionState.Disconnected -> "Disconnected"
        ConnectionState.Connecting -> "Connecting…"
        ConnectionState.Authenticating -> "Authenticating…"
        ConnectionState.Dhcp -> "Getting address…"
        ConnectionState.Connected -> "Connected"
        ConnectionState.Reconnecting -> "Reconnecting…"
    }

    /** "↓ in  ↑ out"; with a duration it is prefixed by it. */
    fun traffic(bytesIn: Long, bytesOut: Long, connectedSeconds: Long? = null): String {
        val t = "↓ ${bytes(bytesIn)}  ↑ ${bytes(bytesOut)}"
        return if (connectedSeconds != null) "${duration(connectedSeconds)}  $t" else t
    }
}

/** Text of the list rows, following the Windows client (client_exe.c) like ServerModel.swift's ListFormat. */
object ListFormat {
    private fun unit(n: Long, word: String) = "$n $word${if (n == 1L) "" else "s"}"

    fun uptime(ms: Long): String {
        val v = maxOf(0, ms)
        return when {
            v < 3_600_001 -> unit(v / 60_000, "min")
            v < 86_400_001 -> unit(v / 3_600_000, "hour")
            else -> unit(v / 86_400_000, "day")
        }
    }

    fun sessions(n: Long): String = unit(n, "session")

    fun logging(logType: String): String {
        val t = logType.lowercase()
        return when {
            t.startsWith("no") -> "No Logs"
            '2' in t && "week" in t -> "2 Weeks"
            t.startsWith("perm") -> "Permanent"
            logType.isEmpty() -> "-"
            else -> logType
        }
    }

    fun ping(ms: Int): String = if (ms == 0) "-" else "$ms ms"

    /** The list is OK within 24 h of its timestamp, older it is "stale". */
    fun isListOk(timestampMs: Long, nowMs: Long): Boolean = Math.abs(nowMs - timestampMs) < 86_400_001
}
