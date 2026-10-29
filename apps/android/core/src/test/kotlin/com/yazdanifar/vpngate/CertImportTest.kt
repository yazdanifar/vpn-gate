package com.yazdanifar.vpngate

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Uses the OpenSSL-made fixtures of the Linux app (crates/vpngate-app-model/testdata). */
class CertImportTest {
    private fun fixture(name: String): ByteArray {
        var dir: File? = File("").absoluteFile
        while (dir != null && !File(dir, "crates/vpngate-app-model/testdata/$name").exists()) dir = dir.parentFile
        return File(checkNotNull(dir), "crates/vpngate-app-model/testdata/$name").readBytes()
    }

    private fun pem(label: String, der: ByteArray) =
        "-----BEGIN $label-----\n${java.util.Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der)}\n-----END $label-----\n".toByteArray()

    @Test
    fun pkcs12GivesTheSameIdentityAsThePemFiles() {
        val cert = CertImport.parseCertificate(fixture("cert.pem"))
        val key = CertImport.parsePrivateKey(fixture("key.pem"))
        for (name in listOf("modern.p12", "legacy.p12")) {
            val id = CertImport.parsePkcs12(fixture(name), "secret")
            assertContentEquals(cert, id.certDer, name)
            assertContentEquals(key, id.privateKeyDer, name)
        }
        CertImport.pair(cert, key)
    }

    @Test
    fun pkcs8AndPkcs1KeysNormaliseToTheSameBytes() {
        val pkcs1 = CertImport.parsePrivateKey(fixture("key.pem"))
        assertContentEquals(pkcs1, CertImport.parsePrivateKey(pem("RSA PRIVATE KEY", pkcs1)))
        assertContentEquals(pkcs1, CertImport.parsePrivateKey(pkcs1))
    }

    @Test
    fun badInputIsExplained() {
        assertTrue(assertFailsWith<CertImportException> { CertImport.parsePkcs12(fixture("modern.p12"), "wrong") }.message!!.contains("passphrase"))
        assertFailsWith<CertImportException> { CertImport.parsePkcs12("not a p12".toByteArray(), "") }
        assertTrue(assertFailsWith<CertImportException> { CertImport.parsePrivateKey(pem("ENCRYPTED PRIVATE KEY", byteArrayOf(1))) }.message!!.contains("passphrase"))
        assertTrue(assertFailsWith<CertImportException> { CertImport.parsePrivateKey(pem("EC PRIVATE KEY", byteArrayOf(1))) }.message!!.contains("RSA"))
        assertFailsWith<CertImportException> { CertImport.parseCertificate("hello".toByteArray()) }
        assertFailsWith<CertImportException> { CertImport.parsePrivateKey("hello".toByteArray()) }
        val cert = CertImport.parseCertificate(fixture("cert.pem"))
        val generated = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().private
        val other = CertImport.parsePrivateKey(pem("PRIVATE KEY", generated.encoded))
        assertFailsWith<CertImportException> { CertImport.pair(cert, other) }
    }
}
