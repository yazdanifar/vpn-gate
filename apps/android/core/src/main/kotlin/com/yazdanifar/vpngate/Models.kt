// Mirrors of the engine's JSON (crates/vpngate-core/src/ipc.rs, docs/cross-platform/IPC.md). Only what the Android UI
// reads or writes; unknown keys are ignored in both directions.
package com.yazdanifar.vpngate

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

object Ipc {
    const val IPC_VERSION = 9

    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }
}

@Serializable
enum class ConnectionState {
    @SerialName("disconnected") Disconnected,
    @SerialName("connecting") Connecting,
    @SerialName("authenticating") Authenticating,
    @SerialName("dhcp") Dhcp,
    @SerialName("connected") Connected,
    @SerialName("reconnecting") Reconnecting,
}

@Serializable
enum class SyncOutcome {
    @SerialName("synced") Synced,
    @SerialName("relaysFailed") RelaysFailed,
    @SerialName("noRelays") NoRelays,
}

@Serializable
enum class ProxyKind {
    @SerialName("none") None,
    @SerialName("http") Http,
    @SerialName("socks5") Socks5,
}

@Serializable
data class ProxySettings(
    val kind: ProxyKind = ProxyKind.None,
    val host: String = "",
    val port: Int = 0,
    val username: String? = null,
    val password: String? = null,
)

/** A state snapshot (a line with `state`). */
@Serializable
data class HelperEvent(
    val state: ConnectionState,
    val server: String? = null,
    val virtualIP: String? = null,
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val log: String? = null,
    val error: String? = null,
    val helperVersion: Int? = null,
    val ipcVersion: Int? = null,
)

@Serializable
data class VpnServer(
    val hostName: String = "",
    val ip: String = "",
    val score: Int = 0,
    val ping: Int = 0,
    val speed: Long = 0,
    val countryLong: String = "",
    val countryShort: String = "",
    val sessions: Int = 0,
    val uptimeMs: Long = 0,
    val totalUsers: Long = 0,
    val totalTraffic: Long = 0,
    val logType: String = "",
    val operatorName: String = "",
    val message: String = "",
    val listedPort: Int = 0,
    val listedProto: String = "",
    val fqdn: String = "",
    val sslPorts: List<Int> = emptyList(),
    val udpPort: Int? = null,
    val openVpnUdpPorts: List<Int> = emptyList(),
    val l2tp: Boolean = false,
    val os: String? = null,
    val soft: String? = null,
    val build: Int? = null,
    val owner: String? = null,
    val abuse: String? = null,
    val numLogin: Long? = null,
    val noLog: Boolean = false,
    val logPermanent: Boolean = false,
    val name: String? = null,
    val pingToGoogle: Int = 0,
    val sendSize: Long = 0,
    val recvSize: Long = 0,
    val isKernelModeNat: Boolean = false,
) {
    /** The DDNS host name is the only unique key: one IP can appear several times on different ports. */
    val id: String get() = hostName

    /** 443, 992, 995, 465, 585, 993, 22 (those offered) first, then the rest, like the Windows client. */
    val prioritizedSslPorts: List<Int>
        get() {
            val first = PREFERRED_PORTS.filter { it in sslPorts }
            return first + sslPorts.filter { it !in first }
        }

    /** Port to try first: the first SSL port in priority order, then the listed port. */
    val connectPort: Int?
        get() = prioritizedSslPorts.firstOrNull() ?: listedPort.takeIf { it in 1..65535 }

    /** Regional-indicator flag emoji, or "" when the country code is not two letters. */
    val flag: String
        get() {
            val s = countryShort.uppercase()
            if (s.length != 2 || s.any { it !in 'A'..'Z' }) return ""
            return s.map { String(Character.toChars(0x1F1E6 + (it - 'A'))) }.joinToString("")
        }

    companion object {
        private val PREFERRED_PORTS = listOf(443, 992, 995, 465, 585, 993, 22)
    }
}

@Serializable
data class ServerListResult(
    val servers: List<VpnServer> = emptyList(),
    /** "HTTP API", "Relay P2P", "Cached", "Built-in" or "CSV Mirror". */
    val source: String = "",
    val timestampMs: Long? = null,
    val isFresh: Boolean = false,
    val outcome: SyncOutcome = SyncOutcome.NoRelays,
    val nextPollSeconds: Double? = null,
)

@Serializable
data class ProbeTarget(val host: String, val ports: List<Int>? = null)

@Serializable
data class ProbeEntry(
    val host: String = "",
    val ok: Boolean = false,
    val port: Int? = null,
    val connectMs: Long? = null,
    val helloMs: Long? = null,
    val build: Long? = null,
    val error: String? = null,
)

@Serializable
data class ProbeResult(val results: List<ProbeEntry> = emptyList())

/** One list server's "Test Connection" state (UI-SPEC 4, probe cell). */
sealed interface Probe {
    data object Queued : Probe
    data object Testing : Probe
    data class Ok(val connectMs: Long, val helloMs: Long?, val port: Int?) : Probe
    data class Failed(val why: String) : Probe

    companion object {
        /** Lower sorts first: working servers by connect time, then untested ones, then failures. */
        fun sortRank(p: Probe?): Long = when (p) {
            is Ok -> p.connectMs
            null, Queued, Testing -> Long.MAX_VALUE - 1
            is Failed -> Long.MAX_VALUE
        }

        fun text(p: Probe?): String = when (p) {
            null -> "—"
            Queued -> "Waiting…"
            Testing -> "Testing…"
            is Ok -> "${p.connectMs} ms"
            is Failed -> p.why
        }
    }
}

/** `ConnectConfig` is not needed here: Android connects with the legacy flat fields of the `connect` request. */
@Serializable
data class ConnectRequest(
    val cmd: String = "connect",
    val host: String,
    val port: Int? = null,
    val ports: List<Int>? = null,
    val proxy: ProxySettings? = null,
    val autoReconnect: Boolean = false,
    @SerialName("blockIPv6") val blockIPv6: Boolean = true,
)
