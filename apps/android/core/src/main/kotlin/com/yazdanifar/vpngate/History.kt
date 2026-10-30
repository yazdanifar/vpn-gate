package com.yazdanifar.vpngate

import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import java.io.File
import java.util.UUID

@Serializable
data class ConnectionLogEntry(
    val id: String = UUID.randomUUID().toString(),
    val serverName: String,
    val serverIp: String,
    val connectedAtMs: Long,
    val disconnectedAtMs: Long? = null,
    val durationSeconds: Double? = null,
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val error: String? = null,
)

/** Connection history (UI-SPEC 9): newest first, at most 100 entries, one per connected period. */
class ConnectionHistoryStore(private val file: File, private val clock: () -> Long = System::currentTimeMillis) {
    var entries: List<ConnectionLogEntry> = try {
        Ipc.json.decodeFromString(ListSerializer(ConnectionLogEntry.serializer()), file.readText())
    } catch (_: Exception) {
        emptyList()
    }
        private set

    var onChange: (() -> Unit)? = null

    fun recordStart(serverName: String, serverIp: String): String {
        val e = ConnectionLogEntry(serverName = serverName, serverIp = serverIp, connectedAtMs = clock())
        entries = (listOf(e) + entries).take(MAX_ENTRIES)
        save()
        return e.id
    }

    fun recordEnd(id: String, bytesIn: Long, bytesOut: Long, error: String?) {
        val i = entries.indexOfFirst { it.id == id }
        if (i < 0) return
        val now = clock()
        val e = entries[i]
        entries = entries.toMutableList().also {
            it[i] = e.copy(
                disconnectedAtMs = now,
                durationSeconds = (now - e.connectedAtMs) / 1000.0,
                bytesIn = bytesIn,
                bytesOut = bytesOut,
                error = error,
            )
        }
        save()
    }

    fun clear() {
        entries = emptyList()
        save()
    }

    private fun save() {
        try {
            file.parentFile?.mkdirs()
            file.writeText(Ipc.json.encodeToString(ListSerializer(ConnectionLogEntry.serializer()), entries))
        } catch (_: java.io.IOException) {
        }
        onChange?.invoke()
    }

    companion object {
        const val MAX_ENTRIES = 100
    }
}
