package com.yazdanifar.vpngate

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonElement
import java.io.File
import java.util.UUID
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/** Where passwords, certificates and keys live (Android Keystore in the app, memory in tests). Never a file. */
interface SecretStore {
    fun get(key: String): String?
    fun set(key: String, value: String)
    fun delete(key: String)
}

class MemorySecretStore : SecretStore {
    val items = mutableMapOf<String, String>()
    override fun get(key: String) = items[key]
    override fun set(key: String, value: String) { items[key] = value }
    override fun delete(key: String) { items.remove(key) }
}

@OptIn(ExperimentalEncodingApi::class)
fun SecretStore.getBytes(key: String): ByteArray? = get(key)?.let { runCatching { Base64.decode(it) }.getOrNull() }

@OptIn(ExperimentalEncodingApi::class)
fun SecretStore.setBytes(key: String, value: ByteArray) = set(key, Base64.encode(value))

/** The four authentication types of a connection setting; the raw strings are the accounts-file and engine values. */
object AuthTypes {
    const val ANONYMOUS = "Anonymous"
    const val PASSWORD = "Standard Password (SHA-0)"
    const val PLAIN_PASSWORD = "Plain Password"
    const val CERTIFICATE = "User Certificate"

    val all = listOf(ANONYMOUS, PASSWORD, PLAIN_PASSWORD, CERTIFICATE)

    fun usesPassword(t: String) = t == PASSWORD || t == PLAIN_PASSWORD
}

@Serializable
enum class RoutingAction {
    @SerialName("proxy") Proxy,
    @SerialName("direct") Direct,
    @SerialName("block") Block,
}

@Serializable
enum class RoutingRuleType {
    @SerialName("domainSuffix") DomainSuffix,
    @SerialName("domainFull") DomainFull,
    @SerialName("domainKeyword") DomainKeyword,
    @SerialName("domainRegex") DomainRegex,
    @SerialName("ip") Ip,
    @SerialName("cidr") Cidr,
}

@Serializable
data class RoutingRule(
    val id: String = UUID.randomUUID().toString(),
    val type: RoutingRuleType,
    val value: String,
    val action: RoutingAction,
    val enabled: Boolean = true,
)

@Serializable
data class RoutingConfig(
    val rules: List<RoutingRule> = emptyList(),
    val defaultAction: RoutingAction = RoutingAction.Proxy,
    val bypassPrivateNetworks: Boolean = false,
) {
    /** True when the config changes nothing: everything through the tunnel, no rules. */
    val isEmpty: Boolean get() = rules.isEmpty() && defaultAction == RoutingAction.Proxy && !bypassPrivateNetworks
}

/** The `config` of a `connect` request (crates/vpngate-core/src/ipc.rs `ConnectConfig`); `Data` fields are base64. */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class ConnectConfig(
    val host: String,
    val ports: List<Int> = listOf(443, 992, 5555, 1194),
    val hubName: String = "VPNGATE",
    val userName: String = "vpn",
    val authType: String = AuthTypes.ANONYMOUS,
    val password: String? = null,
    val certDer: String? = null,
    val privateKeyDer: String? = null,
    val proxy: ProxySettings = ProxySettings(),
    val maxConnection: Int = 1,
    val useCompress: Boolean = false,
    val useUdpAccel: Boolean = true,
    @SerialName("disableQoS") val disableQoS: Boolean = false,
    val halfConnection: Boolean = false,
    val autoReconnect: Boolean = true,
    val reconnectInterval: Double? = null,
    val reconnectCount: Int? = null,
    @SerialName("blockIPv6") val blockIPv6: Boolean = true,
    val checkServerCert: Boolean = false,
    val serverCertFingerprint: String? = null,
    val mtu: Int? = null,
    val virtualMacAddress: String? = null,
    val routing: RoutingConfig? = null,
)

/** `connect` with a full [ConnectConfig]; the engine ignores the flat fields then. */
@Serializable
data class ConfigConnectRequest(val config: ConnectConfig, val cmd: String = "connect")

/** A SoftEther connection setting. Secrets never live here: see [AccountStore]. */
@Serializable
data class ClientAccount(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "",
    val host: String = "",
    val portList: List<Int> = listOf(443, 992, 5555, 1194),
    val hub: String = "DEFAULT",
    val username: String = "",
    val authType: String = AuthTypes.PASSWORD,
    val proxy: ProxySettings = ProxySettings(),
    val checkServerCert: Boolean = false,
    val serverCertFingerprint: String? = null,
    val maxConnection: Int = 1,
    val halfConnection: Boolean = false,
    val compression: Boolean = false,
    val udpAcceleration: Boolean = true,
    val disableQoS: Boolean = false,
    val autoReconnect: Boolean = true,
    val reconnectInterval: Double = 3.0,
    val reconnectCount: Int = 8,
    val virtualMacAddress: String? = null,
    val mtu: Int? = null,
    /** Per-account routing; null means "use the app's global rules". */
    val routing: RoutingConfig? = null,
    val createdAtMs: Long = System.currentTimeMillis(),
    val updatedAtMs: Long = System.currentTimeMillis(),
) {
    /** The account as the engine wants it. [globalRouting] applies only when the account has no rules of its own. */
    @OptIn(ExperimentalEncodingApi::class)
    fun toConnectConfig(
        password: String?,
        certDer: ByteArray?,
        keyDer: ByteArray?,
        blockIPv6: Boolean,
        globalRouting: RoutingConfig?,
    ) = ConnectConfig(
        host = host,
        ports = portList,
        hubName = hub,
        userName = username,
        authType = authType,
        password = password,
        certDer = certDer?.let { Base64.encode(it) },
        privateKeyDer = keyDer?.let { Base64.encode(it) },
        proxy = proxy,
        maxConnection = maxConnection,
        useCompress = compression,
        useUdpAccel = udpAcceleration,
        disableQoS = disableQoS,
        halfConnection = halfConnection,
        autoReconnect = autoReconnect,
        reconnectInterval = reconnectInterval,
        reconnectCount = reconnectCount,
        blockIPv6 = blockIPv6,
        checkServerCert = checkServerCert,
        serverCertFingerprint = serverCertFingerprint,
        mtu = mtu,
        virtualMacAddress = virtualMacAddress,
        routing = routing ?: globalRouting?.takeUnless { it.isEmpty },
    )
}

/** accounts.json plus the secrets in a [SecretStore] (AccountManager.swift). */
class AccountStore(private val file: File, private val secrets: SecretStore, private val clock: () -> Long = System::currentTimeMillis) {
    var accounts: List<ClientAccount> = emptyList()
        private set

    /** Set when the file could not be read completely (the original is kept next to it). */
    var loadNotice: String? = null
        private set

    var onChange: (() -> Unit)? = null

    init {
        load()
    }

    fun load() {
        loadNotice = null
        accounts = emptyList()
        val text = try { file.readText() } catch (_: java.io.IOException) { return }
        val records: List<JsonElement> = try {
            Ipc.json.decodeFromString(ListSerializer(JsonElement.serializer()), text)
        } catch (_: Exception) {
            val kept = setAside(move = true)
            loadNotice = "The saved connection settings could not be read" + (kept?.let { " (kept as $it)." } ?: ".")
            return
        }
        val ok = records.mapNotNull { r ->
            runCatching { Ipc.json.decodeFromJsonElement(ClientAccount.serializer(), r) }.getOrNull()
        }.map { if (it.portList.isEmpty()) it.copy(portList = listOf(443)) else it }
        accounts = ok
        if (ok.size < records.size) {
            val kept = setAside(move = false)
            loadNotice = "${records.size - ok.size} saved connection setting(s) could not be read and were skipped" +
                (kept?.let { " (original kept as $it)." } ?: ".")
        }
    }

    private fun setAside(move: Boolean): String? = try {
        val dest = File(file.parentFile, file.name + ".corrupt-" + clock())
        if (move) file.renameTo(dest) else file.copyTo(dest, overwrite = true)
        dest.name
    } catch (_: java.io.IOException) {
        null
    }

    private fun save() {
        try {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, file.name + ".tmp")
            // The proxy password is a secret: it goes to the secret store, never into this file.
            val safe = accounts.map { it.copy(proxy = it.proxy.copy(password = null)) }
            tmp.writeText(Ipc.json.encodeToString(ListSerializer(ClientAccount.serializer()), safe))
            if (!tmp.renameTo(file)) { file.delete(); tmp.renameTo(file) }
        } catch (_: java.io.IOException) {
        }
        onChange?.invoke()
    }

    private fun key(a: ClientAccount, suffix: String) = "account-${a.id}-$suffix"

    fun password(a: ClientAccount) = secrets.get(key(a, "pw"))
    fun certificate(a: ClientAccount) = secrets.getBytes(key(a, "cert"))

    /** PKCS#1 RSA private key (DER). */
    fun privateKey(a: ClientAccount) = secrets.getBytes(key(a, "key"))
    fun proxyPassword(a: ClientAccount) = secrets.get(key(a, "proxypw"))
    fun hasCertificateIdentity(a: ClientAccount) = certificate(a) != null && privateKey(a) != null

    /** The account with its proxy password filled in, as the engine needs it. */
    fun withProxyPassword(a: ClientAccount): ClientAccount =
        proxyPassword(a)?.let { a.copy(proxy = a.proxy.copy(password = it)) } ?: a

    /** Stores what was given (null keeps the stored value) and returns the account without its proxy password. */
    private fun saveSecrets(a: ClientAccount, password: String?, cert: ByteArray?, keyDer: ByteArray?): ClientAccount {
        if (!password.isNullOrEmpty()) secrets.set(key(a, "pw"), password)
        if (cert != null && cert.isNotEmpty()) secrets.setBytes(key(a, "cert"), cert)
        if (keyDer != null && keyDer.isNotEmpty()) secrets.setBytes(key(a, "key"), keyDer)
        a.proxy.password?.takeIf { it.isNotEmpty() }?.let { secrets.set(key(a, "proxypw"), it) }
        if (a.authType != AuthTypes.CERTIFICATE) { // no stale key material for password accounts
            secrets.delete(key(a, "cert"))
            secrets.delete(key(a, "key"))
        }
        if (!AuthTypes.usesPassword(a.authType)) secrets.delete(key(a, "pw"))
        return a.copy(proxy = a.proxy.copy(password = null))
    }

    fun add(account: ClientAccount, password: String? = null, cert: ByteArray? = null, keyDer: ByteArray? = null) {
        accounts = accounts + saveSecrets(account, password, cert, keyDer)
        save()
    }

    fun update(account: ClientAccount, password: String? = null, cert: ByteArray? = null, keyDer: ByteArray? = null) {
        val i = accounts.indexOfFirst { it.id == account.id }
        if (i < 0) return
        val saved = saveSecrets(account.copy(updatedAtMs = clock()), password, cert, keyDer)
        accounts = accounts.toMutableList().also { it[i] = saved }
        save()
    }

    fun duplicate(account: ClientAccount) {
        val copy = account.copy(
            id = UUID.randomUUID().toString(),
            name = "${account.name} (Copy)",
            createdAtMs = clock(),
            updatedAtMs = clock(),
            proxy = account.proxy.copy(password = proxyPassword(account)),
        )
        accounts = accounts + saveSecrets(copy, password(account), certificate(account), privateKey(account))
        save()
    }

    fun delete(account: ClientAccount) {
        accounts = accounts.filter { it.id != account.id }
        for (s in listOf("pw", "cert", "key", "proxypw")) secrets.delete(key(account, s))
        save()
    }
}

/** The `connect` request for [account], with its secrets from [store]. */
fun AccountStore.connectRequest(account: ClientAccount, blockIPv6: Boolean, globalRouting: RoutingConfig?) =
    ConfigConnectRequest(
        withProxyPassword(account).toConnectConfig(password(account), certificate(account), privateKey(account), blockIPv6, globalRouting),
    )

/** Form state of the connection-setting editor (AccountEditorState.swift); free of UI types so it can be tested. */
data class AccountEditorState(
    val name: String = "New Connection",
    val host: String = "",
    val portString: String = "443, 992, 5555, 1194",
    val hub: String = "DEFAULT",
    val username: String = "",
    val authType: String = AuthTypes.PASSWORD,
    val password: String = "",
    val maxConnection: Int = 1,
    val compression: Boolean = false,
    val udpAcceleration: Boolean = true,
    val useQoS: Boolean = true,
    val halfConnection: Boolean = false,
    val autoReconnect: Boolean = true,
    val reconnectIntervalSeconds: Int = 3,
    val reconnectCount: Int = 8,
    val checkServerCert: Boolean = false,
    val fingerprint: String = "",
    /** Blank = automatic (the DHCP lease decides). */
    val mtuString: String = "",
    /** Blank = random. */
    val macString: String = "",
    val useCustomRouting: Boolean = false,
    val routing: RoutingConfig = RoutingConfig(),
    val proxy: ProxySettings = ProxySettings(),
    /** Freshly imported certificate material (null = keep what is stored). */
    val certDer: ByteArray? = null,
    val privateKeyDer: ByteArray? = null,
    val hasStoredIdentity: Boolean = false,
    val importError: String? = null,
) {
    constructor(account: ClientAccount, password: String? = null, hasStoredIdentity: Boolean = false, proxyPassword: String? = null) : this(
        name = account.name,
        host = account.host,
        portString = account.portList.joinToString(", "),
        hub = account.hub,
        username = account.username,
        authType = account.authType,
        password = password ?: "",
        maxConnection = account.maxConnection,
        compression = account.compression,
        udpAcceleration = account.udpAcceleration,
        useQoS = !account.disableQoS,
        halfConnection = account.halfConnection,
        autoReconnect = account.autoReconnect,
        reconnectIntervalSeconds = Math.round(account.reconnectInterval).toInt(),
        reconnectCount = account.reconnectCount,
        checkServerCert = account.checkServerCert,
        fingerprint = account.serverCertFingerprint ?: "",
        mtuString = account.mtu?.toString() ?: "",
        macString = account.virtualMacAddress ?: "",
        useCustomRouting = account.routing != null,
        routing = account.routing ?: RoutingConfig(),
        proxy = account.proxy.copy(password = proxyPassword ?: account.proxy.password),
        hasStoredIdentity = hasStoredIdentity,
    )

    val parsedPorts: List<Int>
        get() = portString.split(',').mapNotNull { it.trim().toIntOrNull()?.takeIf { n -> n in 1..65535 } }

    val fingerprintError: String?
        get() = fingerprint.trim().let {
            if (it.isEmpty() || InputValidation.normalizedFingerprint(it) != null) null
            else "Fingerprint must be 40 (SHA-1) or 64 (SHA-256) hex digits."
        }

    val certificateReady: Boolean
        get() = authType != AuthTypes.CERTIFICATE || (certDer != null && privateKeyDer != null) || hasStoredIdentity

    val mtuError: String?
        get() = mtuString.trim().let {
            if (it.isEmpty() || it.toIntOrNull()?.let { m -> m in 576..1500 } == true) null
            else "MTU must be 576–1500, or blank for automatic."
        }

    val macError: String?
        get() = macString.trim().let {
            if (it.isEmpty() || InputValidation.parseMacAddress(it) != null) null
            else "MAC must be 6 hex byte pairs, e.g. 00:AC:DE:12:34:56."
        }

    val advancedInvalid: Boolean get() = fingerprintError != null || mtuError != null || macError != null

    val canSave: Boolean
        get() = name.trim().isNotEmpty() && host.trim().isNotEmpty() && InputValidation.isValidHost(host.trim()) &&
            fingerprintError == null && certificateReady && mtuError == null && macError == null &&
            InputValidation.isValidIdentityField(hub) && InputValidation.isValidIdentityField(username)

    /** Starts from [base] (when editing) so fields the form does not show survive. */
    fun makeAccount(base: ClientAccount?): ClientAccount {
        val a = base ?: ClientAccount()
        val ports = parsedPorts
        return a.copy(
            name = name.trim(),
            host = host.trim(),
            portList = ports.ifEmpty { listOf(443) },
            hub = hub.trim().ifEmpty { "DEFAULT" },
            username = username.trim(),
            authType = authType,
            proxy = proxy,
            checkServerCert = checkServerCert,
            serverCertFingerprint = InputValidation.normalizedFingerprint(fingerprint.trim()),
            maxConnection = maxConnection.coerceIn(1, 32),
            compression = compression,
            udpAcceleration = udpAcceleration,
            disableQoS = !useQoS,
            halfConnection = halfConnection,
            autoReconnect = autoReconnect,
            reconnectInterval = maxOf(1, reconnectIntervalSeconds).toDouble(),
            reconnectCount = maxOf(1, reconnectCount),
            mtu = mtuString.trim().toIntOrNull(),
            virtualMacAddress = macString.trim().ifEmpty { null },
            routing = if (useCustomRouting) routing else null,
        )
    }
}
