package com.yazdanifar.vpngate

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** The editors' validation must agree with Tests/Fixtures/golden/validation.json. */
class ValidationTest {
    private fun cases(function: String): JsonArray {
        var dir: File? = File("").absoluteFile
        while (dir != null && !File(dir, "Tests/Fixtures/golden/validation.json").exists()) dir = dir.parentFile
        checkNotNull(dir) { "golden/validation.json not found" }
        val root = Ipc.json.parseToJsonElement(File(dir, "Tests/Fixtures/golden/validation.json").readText()).jsonObject
        return root["cases"]!!.jsonArray.first { it.jsonObject["function"]!!.jsonPrimitive.content == function }
            .jsonObject["cases"]!!.jsonArray
    }

    private fun each(function: String, check: (input: JsonObject, expected: kotlinx.serialization.json.JsonElement) -> Unit) {
        for (c in cases(function)) check(c.jsonObject, c.jsonObject["result"]!!)
    }

    private fun input(c: JsonObject) = c["input"]!!.jsonPrimitive.content

    @Test fun isIPv4Literal() = each("isIPv4Literal") { c, r -> assertEquals(r.jsonPrimitive.booleanOrNull, InputValidation.isIPv4Literal(input(c)), input(c)) }

    @Test fun isValidHost() = each("isValidHost") { c, r -> assertEquals(r.jsonPrimitive.booleanOrNull, InputValidation.isValidHost(input(c)), input(c)) }

    @Test fun isValidPort() = each("isValidPort") { c, r ->
        assertEquals(r.jsonPrimitive.booleanOrNull, InputValidation.isValidPort(c["input"]!!.jsonPrimitive.intOrNull), c.toString())
    }

    @Test fun isIPLiteral() = each("isIPLiteral") { c, r -> assertEquals(r.jsonPrimitive.booleanOrNull, InputValidation.isIPLiteral(input(c)), input(c)) }

    @Test fun isValidIdentityField() = each("isValidIdentityField") { c, r ->
        assertEquals(r.jsonPrimitive.booleanOrNull, InputValidation.isValidIdentityField(input(c)), input(c))
    }

    @Test fun normalizedFingerprint() = each("normalizedFingerprint") { c, r ->
        assertEquals(if (r is JsonNull) null else r.jsonPrimitive.content, InputValidation.normalizedFingerprint(input(c)), input(c))
    }

    @Test fun parseMacAddress() = each("parseMacAddress") { c, r ->
        val got = InputValidation.parseMacAddress(input(c))?.joinToString("") { "%02x".format(it) }
        assertEquals(if (r is JsonNull) null else r.jsonPrimitive.content, got, input(c))
    }

    @Test
    fun routingRuleErrors() {
        assertNull(RoutingRuleValidation.error(RoutingRuleType.DomainSuffix, "example.com"))
        assertNotNull(RoutingRuleValidation.error(RoutingRuleType.DomainSuffix, "bad..com"))
        assertNotNull(RoutingRuleValidation.error(RoutingRuleType.DomainFull, " "))
        assertNull(RoutingRuleValidation.error(RoutingRuleType.Cidr, "10.0.0.0/8"))
        assertNull(RoutingRuleValidation.error(RoutingRuleType.Cidr, "fe80::/10"))
        assertNotNull(RoutingRuleValidation.error(RoutingRuleType.Cidr, "10.0.0.0/33"))
        assertEquals("A CIDR needs a /prefix, e.g. 10.0.0.0/8.", RoutingRuleValidation.error(RoutingRuleType.Cidr, "10.0.0.0"))
        assertNull(RoutingRuleValidation.error(RoutingRuleType.Ip, "::1"))
        assertNotNull(RoutingRuleValidation.error(RoutingRuleType.Ip, "example.com"))
        assertNotNull(RoutingRuleValidation.error(RoutingRuleType.DomainRegex, "(unclosed"))
        assertNull(RoutingRuleValidation.error(RoutingRuleType.DomainRegex, """^(.+\.)?example\.com$"""))
    }
}
