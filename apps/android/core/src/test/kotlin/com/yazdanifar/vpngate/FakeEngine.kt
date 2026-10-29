package com.yazdanifar.vpngate

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** A scriptable engine: records requests and answers v9 requests from [onRequest]. */
class FakeEngine : EngineChannel {
    override var listener: ((String) -> Unit)? = null
    val requests = mutableListOf<JsonObject>()

    /** Return the reply's `result` (or null for `ok:false` with [failure]) per command; null result with no failure = no reply. */
    var onRequest: (cmd: String, request: JsonObject) -> String? = { _, _ -> null }

    override fun send(requestJson: String) {
        val obj = Ipc.json.parseToJsonElement(requestJson).jsonObject
        requests += obj
        val cmd = obj["cmd"]!!.jsonPrimitive.content
        val id = obj["id"]?.jsonPrimitive?.content
        val reply = onRequest(cmd, obj) ?: return
        if (id != null) emit("""{"reply":"$cmd","id":$id,$reply}""")
    }

    fun emit(line: String) = listener?.invoke(line)

    fun event(state: String, server: String? = null, extra: String = "") {
        val s = server?.let { ""","server":"$it"""" } ?: ""
        emit("""{"state":"$state"$s,"bytesIn":0,"bytesOut":0,"ipcVersion":9$extra}""")
    }

    fun commands() = requests.map { it["cmd"]!!.jsonPrimitive.content }
}

fun server(host: String, ip: String, country: String = "Japan", score: Int = 100, ssl: List<Int> = listOf(443), logType: String = "2weeks") =
    VpnServer(hostName = host, ip = ip, countryLong = country, countryShort = "JP", score = score, sslPorts = ssl, logType = logType, listedPort = 1194)

fun listResult(vararg servers: VpnServer, fresh: Boolean = true) = ServerListResult(
    servers = servers.toList(),
    source = "Cached",
    timestampMs = 1_000,
    isFresh = fresh,
    outcome = SyncOutcome.Synced,
)

fun resultJson(r: ServerListResult) = """"ok":true,"result":${Ipc.json.encodeToString(ServerListResult.serializer(), r)}"""
