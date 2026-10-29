package com.yazdanifar.vpngate

import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * The in-process engine as the client sees it: one JSON request per [send], every reply and event back as one JSON line
 * through [listener]. The app implements it over the UniFFI `AndroidEngine`; tests use a fake.
 */
interface EngineChannel {
    /** Receives every line from the engine; set before the first [send]. */
    var listener: ((String) -> Unit)?

    fun send(requestJson: String)
}

enum class RequestFailure { Failed, Timeout, Unsupported }

class EngineRequestException(val kind: RequestFailure, message: String) : Exception(message)

/**
 * The IPC v9 client (docs/cross-platform/IPC.md, "Client rules"): one reader dispatching `reply` lines to the waiting
 * request by `id` and everything with a `state` to [events].
 */
class IpcClient(private val channel: EngineChannel, private val scope: CoroutineScope) {
    private val nextId = AtomicInteger(1)
    private val waiting = ConcurrentHashMap<Int, CancellableContinuation<JsonObject>>()
    private val _events = MutableSharedFlow<HelperEvent>(extraBufferCapacity = 64)

    val events: SharedFlow<HelperEvent> = _events.asSharedFlow()

    init {
        channel.listener = ::onLine
    }

    private fun onLine(line: String) {
        val obj = try {
            Ipc.json.parseToJsonElement(line).jsonObject
        } catch (_: Exception) {
            return
        }
        val reply = obj["reply"]
        if (reply != null) {
            val id = obj["id"]?.jsonPrimitive?.intOrNull ?: return
            waiting.remove(id)?.resume(obj)
        } else if ("state" in obj) {
            val e = try {
                Ipc.json.decodeFromJsonElement<HelperEvent>(obj)
            } catch (_: Exception) {
                return
            }
            _events.tryEmit(e)
        }
    }

    /** A v8 session command (`connect`, `disconnect`, `status`): answered by events, not replies. */
    fun sendCommand(cmd: String, body: JsonObject = JsonObject(emptyMap())) {
        val request = buildJsonObject {
            put("cmd", cmd)
            body.forEach { (k, v) -> put(k, v) }
        }
        channel.send(request.toString())
    }

    /** A v9 request: waits for the reply with the same id and returns its `result`. */
    suspend fun request(cmd: String, body: JsonObject = JsonObject(emptyMap()), timeoutMs: Long = 90_000): JsonElement {
        val id = nextId.getAndIncrement()
        val request = buildJsonObject {
            put("cmd", cmd)
            put("id", id)
            body.forEach { (k, v) -> put(k, v) }
        }
        val reply = try {
            withTimeout(timeoutMs) {
                suspendCancellableCoroutine<JsonObject> { cont ->
                    waiting[id] = cont
                    cont.invokeOnCancellation { waiting.remove(id) }
                    channel.send(request.toString())
                }
            }
        } catch (e: TimeoutCancellationException) {
            throw EngineRequestException(RequestFailure.Timeout, "The engine did not answer in time")
        }
        if (reply["ok"]?.jsonPrimitive?.booleanOrNull != true) {
            throw EngineRequestException(
                RequestFailure.Failed,
                reply["error"]?.jsonPrimitive?.contentOrNull ?: "The engine refused the request",
            )
        }
        return reply["result"] ?: throw EngineRequestException(RequestFailure.Failed, "The engine sent no result")
    }

    private fun proxyBody(proxy: ProxySettings?): JsonObject = buildJsonObject {
        if (proxy != null && proxy.kind != ProxyKind.None) put("proxy", Ipc.json.encodeToJsonElement(proxy))
    }

    /** From the cache or the shipped list; no network. */
    suspend fun listServers(): ServerListResult =
        Ipc.json.decodeFromJsonElement(request("listServers", timeoutMs = 15_000))

    /** Runs the sync pipeline (HTTP API, relay P2P, cached/built-in) and returns the list. */
    suspend fun refreshServers(proxy: ProxySettings? = null): ServerListResult =
        Ipc.json.decodeFromJsonElement(request("refreshServers", proxyBody(proxy)))

    fun connect(request: ConnectRequest) = channel.send(Ipc.json.encodeToString(ConnectRequest.serializer(), request))

    fun disconnect() = sendCommand("disconnect")

    fun status() = sendCommand("status")
}
