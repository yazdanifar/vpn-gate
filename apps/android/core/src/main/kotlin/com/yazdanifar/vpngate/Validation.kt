package com.yazdanifar.vpngate

import java.net.InetAddress

/** Editor validation (InputValidation.swift / crates/vpngate-core/src/validation.rs); pinned by golden/validation.json. */
object InputValidation {
    fun isValidPort(p: Int?): Boolean = p != null && p in 1..65535

    private fun isDigit(c: Char) = c in '0'..'9'

    fun isIPv4Literal(s: String): Boolean {
        val parts = s.split('.')
        return parts.size == 4 && parts.all { p -> p.length in 1..3 && p.all(::isDigit) && p.toInt() <= 255 }
    }

    /** IPv4 literal or RFC 1123 hostname. Never starts with '-' (would be parsed as an option). */
    fun isValidHost(s: String): Boolean {
        if (s.isEmpty() || s.length > 253) return false
        if (isIPv4Literal(s)) return true
        if (s.all { isDigit(it) || it == '.' }) return false // malformed dotted number
        if (s.first() == '-' || s.first() == '.' || s.last() == '.' || s.last() == '-') return false
        return s.all { it in 'a'..'z' || it in 'A'..'Z' || isDigit(it) || it == '-' || it == '.' } && ".." !in s
    }

    private fun isHex(c: Char) = isDigit(c) || c in 'a'..'f' || c in 'A'..'F'

    /** SHA-1 (40) or SHA-256 (64) hex digits, ':' ' ' '-' separators allowed. Returns bare lowercase hex or null. */
    fun normalizedFingerprint(s: String): String? {
        val hex = s.filter { !it.isWhitespace() && it != ':' && it != '-' }.lowercase()
        return hex.takeIf { it.length == 40 || it.length == 64 }?.takeIf { it.all(::isHex) }
    }

    /** 6 hex byte pairs separated by ':' or '-'. */
    fun parseMacAddress(s: String): ByteArray? {
        val parts = s.split(':', '-').filter { it.isNotEmpty() }
        if (parts.size != 6) return null
        return ByteArray(6) { i ->
            val p = parts[i]
            if (p.length !in 1..2 || !p.all(::isHex)) return null
            p.toInt(16).toByte()
        }
    }

    /** Hub and user names travel in the SoftEther handshake: at most 255 bytes, no NUL. */
    fun isValidIdentityField(s: String): Boolean = s.toByteArray(Charsets.UTF_8).size <= 255 && '\u0000' !in s

    /** A bare IPv4 or IPv6 address (no "/prefix"). */
    fun isIPLiteral(s: String): Boolean {
        if ('/' in s || '%' in s) return false
        if (':' !in s) return isIPv4Literal(s)
        // The shared matcher does not accept IPv4-mapped tails ("::ffff:1.2.3.4").
        return '.' !in s && isIPv6(s)
    }

    internal fun isIPv6(s: String): Boolean {
        if (!s.all { isHex(it) || it == ':' }) return false // keeps InetAddress from resolving names
        return runCatching { InetAddress.getByName(s) is java.net.Inet6Address }.getOrDefault(false)
    }
}

/** Per-type validation of a routing rule's value (RoutingRule::validation_error). */
object RoutingRuleValidation {
    class TypeInfo(val type: RoutingRuleType, val label: String, val placeholder: String)

    val types = listOf(
        TypeInfo(RoutingRuleType.DomainSuffix, "Domain suffix", "example.com"),
        TypeInfo(RoutingRuleType.DomainFull, "Domain (exact)", "example.com"),
        TypeInfo(RoutingRuleType.DomainKeyword, "Domain keyword", "ads"),
        TypeInfo(RoutingRuleType.DomainRegex, "Domain regex", """^(.+\.)?example\.com$"""),
        TypeInfo(RoutingRuleType.Ip, "IP address", "203.0.113.5"),
        TypeInfo(RoutingRuleType.Cidr, "IP range (CIDR)", "10.0.0.0/8"),
    )

    private fun isBlank(c: Char) =
        c == ' ' || c == '\t' || c == ' ' || c == ' ' || c in ' '..' ' || c == ' ' || c == ' ' || c == '　'

    /** Null when [value] is well-formed for [type]; else a short message. */
    fun error(type: RoutingRuleType, value: String): String? {
        val v = value.trim(::isBlank)
        if (v.isEmpty()) return "Value is required."
        return when (type) {
            RoutingRuleType.DomainSuffix, RoutingRuleType.DomainFull ->
                if (isPlausibleDomain(v)) null else "Not a valid domain name."
            RoutingRuleType.DomainKeyword -> null
            RoutingRuleType.DomainRegex ->
                try { Regex(v); null } catch (_: IllegalArgumentException) { "Not a valid regular expression." }
            RoutingRuleType.Ip -> if (InputValidation.isIPLiteral(v)) null else "Not a valid IPv4 or IPv6 address."
            RoutingRuleType.Cidr -> when {
                '/' !in v -> "A CIDR needs a /prefix, e.g. 10.0.0.0/8."
                isCidr(v) -> null
                else -> "Not a valid CIDR range."
            }
        }
    }

    fun error(rule: RoutingRule): String? = error(rule.type, rule.value)

    /** Rule types the Android tunnel can apply (see [RoutingConfig.forAndroid]). */
    val androidTypes = types.filter { it.type == RoutingRuleType.Ip || it.type == RoutingRuleType.Cidr }

    /** Null when the Android tunnel can honour [rule]: an IPv4 address or range sent around the VPN. */
    fun androidError(rule: RoutingRule): String? {
        if (rule.type != RoutingRuleType.Ip && rule.type != RoutingRuleType.Cidr) return "Only IP address and range rules work on Android."
        if (rule.action != RoutingAction.Direct) return "Only rules that bypass the VPN work on Android."
        if (!rule.enabled) return "disabled"
        error(rule)?.let { return it }
        val addr = rule.value.trim().substringBefore('/')
        return if (InputValidation.isIPv4Literal(addr)) null else "Only IPv4 addresses work on Android."
    }

    /** Message for the editor's value field: the generic check plus the IPv4-only limit. */
    fun androidValueError(type: RoutingRuleType, value: String): String? {
        error(type, value)?.let { return it }
        return if (InputValidation.isIPv4Literal(value.trim().substringBefore('/'))) null else "Only IPv4 addresses work on Android."
    }

    private fun isPlausibleDomain(s: String) =
        s.length <= 253 && s.first() != '.' && s.last() != '.' && ".." !in s &&
            s.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '.' }

    private fun isCidr(s: String): Boolean {
        val i = s.indexOf('/')
        val addr = s.substring(0, i)
        val prefix = s.substring(i + 1)
        val v4 = InputValidation.isIPv4Literal(addr)
        if (!v4 && !(':' in addr && '.' !in addr && InputValidation.isIPv6(addr))) return false
        if (prefix.isEmpty() || prefix.length > 3 || !prefix.all { it in '0'..'9' }) return false
        return prefix.toInt() <= if (v4) 32 else 128
    }
}
