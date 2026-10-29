package com.yazdanifar.vpngate

import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class CertImportException(message: String) : Exception(message)

/**
 * Turns user-supplied certificate / key files into the DER blobs the engine needs: the certificate (X.509 DER) and an RSA
 * private key as PKCS#1 `RSAPrivateKey` DER (CertImport.swift). Only RSA is supported; nothing here touches disk.
 */
object CertImport {
    class Identity(val certDer: ByteArray, val privateKeyDer: ByteArray)

    fun parseCertificate(data: ByteArray): ByteArray {
        val der = pemBlocks(data).firstOrNull { it.label == "CERTIFICATE" || it.label == "X509 CERTIFICATE" }?.der
            ?: data.takeIf { it.isNotEmpty() && it[0] == 0x30.toByte() }
            ?: throw notCertificate()
        try {
            CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der))
        } catch (_: CertificateException) {
            throw notCertificate()
        }
        return der
    }

    /** Accepts PKCS#1 (`RSA PRIVATE KEY`), PKCS#8 (`PRIVATE KEY`) or raw DER of either; returns PKCS#1 DER. */
    fun parsePrivateKey(data: ByteArray): ByteArray {
        var der: ByteArray? = null
        for (b in pemBlocks(data)) {
            when (b.label) {
                "ENCRYPTED PRIVATE KEY" -> throw encrypted()
                "EC PRIVATE KEY" -> throw unsupported("EC")
                "DSA PRIVATE KEY" -> throw unsupported("DSA")
                "RSA PRIVATE KEY" -> {
                    if (b.headers.any { it.contains("encrypted", ignoreCase = true) }) throw encrypted()
                    der = b.der
                }
                "PRIVATE KEY" -> der = b.der
            }
            if (der != null) break
        }
        val raw = der ?: data.takeIf { it.isNotEmpty() && it[0] == 0x30.toByte() } ?: throw notKey()
        return toPkcs1(raw)
    }

    /** A PKCS#12 / PFX file; the key must be RSA and belong to the certificate. */
    fun parsePkcs12(data: ByteArray, passphrase: String): Identity {
        val store = KeyStore.getInstance("PKCS12")
        try {
            store.load(ByteArrayInputStream(data), passphrase.toCharArray())
        } catch (e: java.io.IOException) {
            // The JDK reports a wrong passphrase as an IOException caused by an UnrecoverableKeyException / bad MAC.
            val msg = generateSequence<Throwable>(e) { it.cause }.joinToString(" ") { it.message.orEmpty() }
            if (msg.contains("password", ignoreCase = true) || msg.contains("MAC", ignoreCase = true) ||
                msg.contains("Unrecoverable", ignoreCase = true)
            ) throw CertImportException("Wrong passphrase for the .p12 file.")
            throw CertImportException("Could not read the .p12 file: ${e.message}")
        } catch (e: java.security.GeneralSecurityException) {
            throw CertImportException("Could not read the .p12 file: ${e.message}")
        }
        val alias = store.aliases().toList().firstOrNull { store.isKeyEntry(it) }
            ?: throw CertImportException("Could not read the .p12 file: it holds no private key.")
        val key = try {
            store.getKey(alias, passphrase.toCharArray())
        } catch (_: java.security.GeneralSecurityException) {
            throw CertImportException("Wrong passphrase for the .p12 file.")
        }
        if (key !is RSAPrivateKey) throw unsupported("not RSA")
        val cert = store.getCertificate(alias) as? X509Certificate
            ?: throw CertImportException("Could not read the .p12 file: it holds no certificate.")
        return pair(cert.encoded, toPkcs1(key.encoded))
    }

    /** Checks that [keyDer] (PKCS#1) is the private half of [certDer]. */
    fun pair(certDer: ByteArray, keyDer: ByteArray): Identity {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
        val pub = cert.publicKey as? RSAPublicKey ?: throw unsupported("not RSA")
        val priv = rsaKey(keyDer) ?: throw notKey()
        if (pub.modulus != priv.modulus) throw CertImportException("The private key does not belong to the certificate.")
        return Identity(certDer, keyDer)
    }

    private fun encrypted() = CertImportException(
        "The private key is passphrase-protected. Remove the passphrase first (openssl rsa -in key.pem -out plain.pem) or import a .p12 file instead.",
    )

    private fun unsupported(t: String) = CertImportException("Only RSA keys are supported for certificate login (this key is $t).")

    private fun notKey() = CertImportException("That file is not an RSA private key (PEM or DER expected).")

    private fun notCertificate() = CertImportException("That file is not an X.509 certificate (PEM or DER expected).")

    // region DER

    private val RSA_OID = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x01)
    private val EC_OID = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01)

    private fun contains(hay: ByteArray, needle: ByteArray): Boolean =
        (0..hay.size - needle.size).any { i -> needle.indices.all { hay[i + it] == needle[it] } }

    /** The PKCS#1 key inside a PKCS#8 wrapper, or [der] itself when it already is PKCS#1. */
    private fun toPkcs1(der: ByteArray): ByteArray {
        val pkcs8 = try { KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(der)) } catch (_: Exception) { null }
        if (pkcs8 is RSAPrivateKey) return unwrapPkcs8(pkcs8.encoded) ?: throw notKey()
        if (rsaKey(der) != null) return der
        if (contains(der, EC_OID)) throw unsupported("EC")
        throw notKey()
    }

    /** Parses a PKCS#1 RSAPrivateKey by wrapping it in PKCS#8, which is all `KeyFactory` reads. */
    private fun rsaKey(pkcs1: ByteArray): RSAPrivateKey? = try {
        val algorithm = byteArrayOf(0x30, 0x0D) + RSA_OID.let { byteArrayOf(0x06, it.size.toByte()) + it } + byteArrayOf(0x05, 0x00)
        val body = byteArrayOf(0x02, 0x01, 0x00) + algorithm + tlv(0x04, pkcs1)
        KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(tlv(0x30, body))) as RSAPrivateKey
    } catch (_: Exception) {
        null
    }

    private fun tlv(tag: Int, content: ByteArray): ByteArray {
        val n = content.size
        val len = when {
            n < 0x80 -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            n < 0x10000 -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
            else -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
        }
        return byteArrayOf(tag.toByte()) + len + content
    }

    /** PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm SEQUENCE, privateKey OCTET STRING }. */
    private fun unwrapPkcs8(der: ByteArray): ByteArray? {
        var p = 0
        fun readHeader(expect: Int): Int? {
            if (p >= der.size || (der[p].toInt() and 0xFF) != expect) return null
            p++
            val first = der.getOrNull(p++)?.toInt()?.and(0xFF) ?: return null
            if (first < 0x80) return first
            var n = 0
            repeat(first and 0x7F) { n = (n shl 8) or ((der.getOrNull(p++)?.toInt() ?: return null) and 0xFF) }
            return n
        }
        readHeader(0x30) ?: return null
        val vLen = readHeader(0x02) ?: return null
        p += vLen
        val aLen = readHeader(0x30) ?: return null
        p += aLen
        val oLen = readHeader(0x04) ?: return null
        return der.copyOfRange(p, minOf(p + oLen, der.size))
    }

    // endregion

    internal class PemBlock(val label: String, val headers: List<String>, val der: ByteArray)

    @OptIn(ExperimentalEncodingApi::class)
    internal fun pemBlocks(data: ByteArray): List<PemBlock> {
        val text = try {
            Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(data)).toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
            return emptyList()
        }
        val lines = text.split('\n').map { it.trim() }
        val blocks = mutableListOf<PemBlock>()
        var i = 0
        while (i < lines.size) {
            val line = lines[i]
            if (!line.startsWith("-----BEGIN ") || !line.endsWith("-----")) { i++; continue }
            val label = line.substring(11, line.length - 5)
            val end = "-----END $label-----"
            val headers = mutableListOf<String>()
            val body = StringBuilder()
            var j = i + 1
            while (j < lines.size && lines[j] != end) {
                if (':' in lines[j]) headers += lines[j] else body.append(lines[j])
                j++
            }
            if (j == lines.size) break
            runCatching { Base64.decode(body.toString()) }.getOrNull()?.let { blocks += PemBlock(label, headers, it) }
            i = j + 1
        }
        return blocks
    }
}
