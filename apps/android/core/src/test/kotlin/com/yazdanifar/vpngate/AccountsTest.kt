package com.yazdanifar.vpngate

import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AccountsTest {
    private val dir: File = Files.createTempDirectory("vpngate-accounts").toFile().also { it.deleteOnExit() }
    private val file = File(dir, "accounts.json")
    private val secrets = MemorySecretStore()
    private fun store() = AccountStore(file, secrets)

    private fun form(host: String = "vpn.example.com") = AccountEditorState(name = "Work", host = host, username = "alice", password = "hunter2")

    @Test
    fun editorStateBuildsAnAccountAndValidates() {
        val s = form().copy(portString = "443, 99999, x, 1194", mtuString = "1400", macString = "00:AC:DE:12:34:56")
        assertTrue(s.canSave)
        val a = s.makeAccount(null)
        assertEquals(listOf(443, 1194), a.portList)
        assertEquals(1400, a.mtu)
        assertFalse(form(host = "-bad").canSave)
        assertFalse(form().copy(mtuString = "100").canSave)
        assertFalse(form().copy(macString = "zz").canSave)
        assertFalse(form().copy(fingerprint = "12").canSave)
        assertFalse(form().copy(authType = AuthTypes.CERTIFICATE).canSave)
        assertTrue(form().copy(authType = AuthTypes.CERTIFICATE, hasStoredIdentity = true).canSave)
        assertEquals(listOf(443), form().copy(portString = "zzz").makeAccount(null).portList)
    }

    @Test
    fun secretsNeverReachTheFile() {
        val st = store()
        val a = form().copy(proxy = ProxySettings(ProxyKind.Http, "p.example", 8080, "u", "proxy-secret")).makeAccount(null)
        st.add(a, password = "hunter2")
        val text = file.readText()
        assertFalse("hunter2" in text)
        assertFalse("proxy-secret" in text)
        val reloaded = store().accounts.single()
        assertEquals("p.example", reloaded.proxy.host)
        assertNull(reloaded.proxy.password)
        assertEquals("hunter2", st.password(a))
        assertEquals("proxy-secret", st.proxyPassword(a))
    }

    @Test
    fun connectConfigCarriesSecretsAndRouting() {
        val st = store()
        val a = form().makeAccount(null)
        st.add(a, password = "pw")
        val global = RoutingConfig(bypassPrivateNetworks = true)
        val req = st.connectRequest(st.accounts.single().copy(proxy = ProxySettings(ProxyKind.Socks5, "h", 1, null, null)), blockIPv6 = false, globalRouting = global)
        val json = Ipc.json.parseToJsonElement(Ipc.json.encodeToString(ConfigConnectRequest.serializer(), req)).jsonObject
        assertEquals("connect", json["cmd"]!!.jsonPrimitive.content)
        val cfg = json["config"]!!.jsonObject
        assertEquals("pw", cfg["password"]!!.jsonPrimitive.content)
        assertEquals("false", cfg["blockIPv6"]!!.jsonPrimitive.content)
        assertEquals("false", cfg["disableQoS"]!!.jsonPrimitive.content)
        assertEquals("vpn.example.com", cfg["host"]!!.jsonPrimitive.content)
        assertTrue("routing" in cfg)
        // an account's own rules win over the global ones, and an empty global config is omitted
        val own = RoutingConfig(defaultAction = RoutingAction.Direct)
        assertEquals(own, a.copy(routing = own).toConnectConfig(null, null, null, true, global).routing)
        assertNull(a.toConnectConfig(null, null, null, true, RoutingConfig()).routing)
    }

    @Test
    fun updateDuplicateDeleteAndStaleSecrets() {
        val st = store()
        val a = form().makeAccount(null)
        st.add(a, password = "pw")
        st.update(a.copy(authType = AuthTypes.ANONYMOUS))
        assertNull(st.password(a), "an anonymous account keeps no password")
        st.update(a.copy(authType = AuthTypes.PASSWORD), password = "pw2")
        st.duplicate(st.accounts.single())
        assertEquals(2, st.accounts.size)
        val copy = st.accounts.last()
        assertEquals("Work (Copy)", copy.name)
        assertEquals("pw2", st.password(copy))
        st.delete(copy)
        assertNull(st.password(copy))
        assertEquals(1, store().accounts.size)
    }

    @Test
    fun certificateAccountsDropKeysWhenSwitchedToPassword() {
        val st = store()
        val a = form().copy(authType = AuthTypes.CERTIFICATE, certDer = byteArrayOf(1, 2), privateKeyDer = byteArrayOf(3)).makeAccount(null)
        st.add(a, cert = byteArrayOf(1, 2), keyDer = byteArrayOf(3))
        assertTrue(st.hasCertificateIdentity(a))
        assertContentEquals(byteArrayOf(1, 2), st.certificate(a))
        st.update(a.copy(authType = AuthTypes.PASSWORD), password = "x")
        assertFalse(st.hasCertificateIdentity(a))
    }

    @Test
    fun corruptFileIsSetAsideAndSkippedRecordsAreCounted() {
        file.writeText("not json")
        val broken = store()
        assertTrue(broken.accounts.isEmpty())
        assertNotNull(broken.loadNotice)
        assertFalse(file.exists())
        assertTrue(dir.listFiles()!!.any { it.name.startsWith("accounts.json.corrupt-") })

        file.writeText("""[{"name":"ok","host":"a.example"},{"name":5}]""")
        val partial = store()
        assertEquals(listOf("ok"), partial.accounts.map { it.name })
        assertTrue(partial.loadNotice!!.startsWith("1 saved connection"))
    }

    @Test
    fun historyKeepsNewestFirstAndCapsAtOneHundred() {
        var now = 1_000L
        val h = ConnectionHistoryStore(File(dir, "history.json")) { now }
        val first = h.recordStart("a", "1.1.1.1")
        now += 5_000
        h.recordEnd(first, 10, 20, null)
        repeat(105) { h.recordStart("s$it", "2.2.2.2") }
        assertEquals(100, h.entries.size)
        assertEquals("s104", h.entries.first().serverName)
        val reloaded = ConnectionHistoryStore(File(dir, "history.json")) { now }
        assertEquals(100, reloaded.entries.size)
        val other = ConnectionHistoryStore(File(dir, "h2.json")) { now }
        val id = other.recordStart("x", "3.3.3.3")
        now += 2_000
        other.recordEnd(id, 1, 2, "boom")
        assertEquals(2.0, other.entries.single().durationSeconds)
        assertEquals("boom", other.entries.single().error)
        other.clear()
        assertTrue(other.entries.isEmpty())
    }
}
