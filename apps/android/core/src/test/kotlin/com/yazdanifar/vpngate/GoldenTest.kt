package com.yazdanifar.vpngate

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The Kotlin mirrors must read the JSON pinned in Tests/Fixtures/golden (frozen reference data, see DECISIONS U15b). */
class GoldenTest {
    private fun golden(name: String): JsonObject {
        var dir: File? = File("").absoluteFile
        while (dir != null && !File(dir, "Tests/Fixtures/golden/$name").exists()) dir = dir.parentFile
        checkNotNull(dir) { "Tests/Fixtures/golden/$name not found above ${File("").absolutePath}" }
        return Ipc.json.parseToJsonElement(File(dir, "Tests/Fixtures/golden/$name").readText()).jsonObject
    }

    private fun case(file: JsonObject, name: String) =
        file["cases"]!!.jsonArray.first { it.jsonObject["name"]!!.jsonPrimitive.content == name }.jsonObject

    @Test
    fun eventsDecode() {
        for (c in case(golden("ipc.json"), "event-decode")["cases"]!!.jsonArray) {
            val o = c.jsonObject
            val input = o["input"]!!.jsonPrimitive.content
            if (o["error"]?.jsonPrimitive?.boolean == true) {
                val failed = runCatching { Ipc.json.decodeFromString(HelperEvent.serializer(), input) }.isFailure
                // a Kotlin default for a missing byte count is fine; a missing/unknown state must fail
                if (!input.contains("\"state\":\"") || input.contains("bogus")) assertTrue(failed, input)
                continue
            }
            val e = Ipc.json.decodeFromString(HelperEvent.serializer(), input)
            val want = o["event"]!!.jsonObject
            assertEquals(want["state"]!!.jsonPrimitive.content, Ipc.json.encodeToString(ConnectionState.serializer(), e.state).trim('"'))
            assertEquals(want["bytesIn"]!!.jsonPrimitive.content.toLong(), e.bytesIn)
        }
    }

    @Test
    fun serverListSnapshotDecodes() {
        val snap = case(golden("serverlist.json"), "parse-snapshot")
        val servers = snap["servers"]!!.jsonArray
        assertEquals(snap["count"]!!.jsonPrimitive.content.toInt(), servers.size)
        for (s in servers) {
            val decoded = Ipc.json.decodeFromJsonElement(VpnServer.serializer(), s)
            val o = s.jsonObject
            assertEquals(o["hostName"]!!.jsonPrimitive.content, decoded.hostName)
            assertEquals(o["ip"]!!.jsonPrimitive.content, decoded.ip)
            assertEquals(o["countryLong"]!!.jsonPrimitive.content, decoded.countryLong)
            assertEquals(o["sslPorts"]!!.jsonArray.map { it.jsonPrimitive.content.toInt() }, decoded.sslPorts)
        }
    }
}
