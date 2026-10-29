package com.yazdanifar.vpngate

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** Asks the system for the VPN consent dialog and brings the VpnService up; false when the user said no. */
fun interface VpnPreparer {
    suspend fun prepare(): Boolean
}

data class UiState(
    val state: ConnectionState = ConnectionState.Disconnected,
    val server: String? = null,
    val virtualIp: String? = null,
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val connectedAtMs: Long? = null,
    val notice: String? = null,
    val showDisclaimer: Boolean = false,
    val isLoading: Boolean = false,
    val listError: String? = null,
    val listSource: String? = null,
    val listTimestampMs: Long? = null,
    val allServers: List<VpnServer> = emptyList(),
    val filter: ServerFilter = ServerFilter(),
    val favorites: Set<String> = emptySet(),
    val sortKey: SortKey = SortKey.Score,
    val sortDescending: Boolean = true,
    val selectedId: String? = null,
    val logLines: List<String> = emptyList(),
    val accounts: List<ClientAccount> = emptyList(),
    val accountsNotice: String? = null,
    val history: List<ConnectionLogEntry> = emptyList(),
    val proxy: ProxySettings = ProxySettings(),
    val autoReconnect: Boolean = true,
    val blockIPv6: Boolean = true,
    val globalRouting: RoutingConfig = RoutingConfig(),
) {
    /** The filtered, sorted rows. */
    val servers: List<VpnServer> get() = filter.apply(allServers, favorites).sortedBy(sortKey, sortDescending)

    val countries: List<String> get() = allServers.map { it.countryLong }.filter { it.isNotEmpty() }.distinct().sorted()

    val selected: VpnServer? get() = allServers.firstOrNull { it.id == selectedId }

    val isBusy: Boolean get() = state != ConnectionState.Disconnected && state != ConnectionState.Connected

    val canConnect: Boolean get() = state == ConnectionState.Disconnected && selected != null

    val stateTitle: String get() = Fmt.title(state)

    val serverName: String?
        get() = server?.let { ip -> allServers.firstOrNull { it.ip == ip }?.hostName ?: ip }

    fun trafficText(nowMs: Long): String =
        Fmt.traffic(bytesIn, bytesOut, connectedAtMs?.let { (nowMs - it) / 1000 })

    /** UI-SPEC 4, "List status line". */
    fun listStatus(nowMs: Long): String = when {
        listError != null -> "List update failed ($listError). Try again."
        isLoading && allServers.isEmpty() -> "Refreshing the List… (about 1 MB, can take 10–20 s)"
        isLoading -> "Refreshing the List…"
        allServers.isEmpty() -> "No servers yet. Press Refresh List."
        else -> {
            val shown = servers.size
            val base = "${allServers.size} Public VPN Relay Servers on the Earth!"
            val showing = if (shown != allServers.size) " — showing $shown" else ""
            if (listTimestampMs != null && !ListFormat.isListOk(listTimestampMs, nowMs)) {
                "$base$showing. The list is old — press Refresh List."
            } else {
                base + showing
            }
        }
    }
}

/**
 * The main screen's logic (UI-SPEC sections 1, 4, 10, 11), free of Android types. [scope] runs on the main thread in
 * the app and on a test scheduler in tests.
 */
class MainModel(
    private val ipc: IpcClient,
    private val settings: SettingsStore,
    private val scope: CoroutineScope,
    private val preparer: VpnPreparer,
    private val clock: () -> Long = System::currentTimeMillis,
    private val reconnectDelayMs: Long = 15_000,
    private val answerTimeoutMs: Long = 10_000,
    private val accountStore: AccountStore? = null,
    private val historyStore: ConnectionHistoryStore? = null,
) {
    private val _state = MutableStateFlow(
        UiState(
            showDisclaimer = !settings.hasAgreedToDisclaimer,
            favorites = settings.favorites,
            accounts = accountStore?.accounts.orEmpty(),
            accountsNotice = accountStore?.loadNotice,
            history = historyStore?.entries.orEmpty(),
            proxy = settings.proxy,
            autoReconnect = settings.autoReconnect,
            blockIPv6 = settings.blockIPv6,
            globalRouting = settings.globalRouting,
        ),
    )
    val state: StateFlow<UiState> = _state.asStateFlow()

    private var hasAgreed = settings.hasAgreedToDisclaimer
    private var parked: (() -> Unit)? = null
    private var wanted: VpnServer? = null
    private var reconnectJob: Job? = null
    private var connectSeq = 0
    private var lastEventAt = Long.MIN_VALUE
    private var reconnectAttempts = 0
    private val log = ArrayDeque<String>()
    private var started = false
    private var openHistoryId: String? = null

    /** Subscribes to the engine's events, asks for a snapshot and loads the list (cache first, then a refresh). */
    fun start() {
        if (started) return
        started = true
        scope.launch { ipc.events.collect(::applyEvent) }
        ipc.status()
        scope.launch {
            val cached = load { ipc.listServers() }
            if (cached == null || !cached.isFresh) refreshList()
        }
    }

    // region disclaimer

    private fun requireAgreement(resume: () -> Unit): Boolean {
        if (hasAgreed) return true
        parked = resume
        _state.update { it.copy(showDisclaimer = true) }
        return false
    }

    fun agree() {
        hasAgreed = true
        settings.hasAgreedToDisclaimer = true
        _state.update { it.copy(showDisclaimer = false) }
        parked?.also { parked = null }?.invoke()
    }

    /** The caller closes the app. */
    fun disagree() {
        parked = null
    }

    // endregion

    // region list

    fun refreshList() {
        scope.launch { load { ipc.refreshServers(settings.proxy.takeIf { it.kind != ProxyKind.None }) } }
    }

    private suspend fun load(fetch: suspend () -> ServerListResult): ServerListResult? {
        _state.update { it.copy(isLoading = true, listError = null) }
        return try {
            val r = fetch()
            _state.update {
                it.copy(
                    isLoading = false,
                    allServers = r.servers,
                    listSource = r.source,
                    listTimestampMs = r.timestampMs,
                    selectedId = it.selectedId?.takeIf { id -> r.servers.any { s -> s.id == id } },
                )
            }
            r
        } catch (e: EngineRequestException) {
            _state.update { it.copy(isLoading = false, listError = e.message) }
            null
        }
    }

    fun select(server: VpnServer?) = _state.update { it.copy(selectedId = server?.id) }

    fun setSearch(text: String) = _state.update { it.copy(filter = it.filter.copy(search = text)) }

    fun setCountry(country: String) = _state.update { it.copy(filter = it.filter.copy(country = country)) }

    fun setFavoritesOnly(on: Boolean) = _state.update { it.copy(filter = it.filter.copy(favoritesOnly = on)) }

    fun setMaxLogWeeks(weeks: Int?) = _state.update { it.copy(filter = it.filter.copy(maxLogWeeks = weeks)) }

    fun clearFilters() = _state.update { it.copy(filter = ServerFilter()) }

    fun sortBy(key: SortKey) = _state.update {
        if (it.sortKey == key) it.copy(sortDescending = !it.sortDescending)
        else it.copy(sortKey = key, sortDescending = key == SortKey.Score || key == SortKey.Speed || key == SortKey.Uptime)
    }

    fun toggleFavorite(server: VpnServer) {
        val next = _state.value.favorites.let { if (server.id in it) it - server.id else it + server.id }
        settings.favorites = next
        _state.update { it.copy(favorites = next) }
    }

    // endregion

    // region events

    fun applyEvent(e: HelperEvent) {
        lastEventAt = clock()
        // A "disconnected" event carries zeroed counters; the totals are those of the last event before it.
        if (e.state != ConnectionState.Disconnected) {
            lastBytesIn = e.bytesIn
            lastBytesOut = e.bytesOut
        }
        if (e.ipcVersion != null && e.ipcVersion < Ipc.IPC_VERSION) {
            _state.update { it.copy(notice = "The VPN engine is too old for this app. Update VPN Gate.") }
        }
        e.log?.takeIf { it.isNotEmpty() }?.let(::appendLog)
        if (!e.error.isNullOrEmpty()) {
            appendLog("Error: ${e.error}")
            _state.update { it.copy(notice = e.error) }
        }
        // While a reconnect is pending the engine's own "disconnected" must not wipe the "Reconnecting…" state.
        val holdReconnecting = reconnectJob != null && e.state == ConnectionState.Disconnected
        _state.update {
            val s = if (holdReconnecting) it else it.copy(state = e.state, server = e.server, virtualIp = e.virtualIP)
            s.copy(
                bytesIn = e.bytesIn,
                bytesOut = e.bytesOut,
                logLines = log.toList(),
                connectedAtMs = when (e.state) {
                    ConnectionState.Connected -> it.connectedAtMs ?: clock()
                    ConnectionState.Disconnected -> null
                    else -> it.connectedAtMs
                },
                notice = if (e.state == ConnectionState.Connected) null else s.notice,
            )
        }
        when (e.state) {
            ConnectionState.Connected -> {
                reconnectAttempts = 0
                startHistory(e)
            }
            ConnectionState.Disconnected -> {
                endHistory(e)
                considerReconnect()
            }
            else -> {}
        }
    }

    // One history entry per connected period (UI-SPEC 9).
    private fun startHistory(e: HelperEvent) {
        val store = historyStore ?: return
        if (openHistoryId != null) return
        val ip = e.server ?: _state.value.server ?: return
        val name = _state.value.allServers.firstOrNull { it.ip == ip }?.hostName ?: accountName ?: ip
        openHistoryId = store.recordStart(name, ip)
        _state.update { it.copy(history = store.entries) }
    }

    private fun endHistory(e: HelperEvent) {
        val store = historyStore ?: return
        val id = openHistoryId ?: return
        openHistoryId = null
        store.recordEnd(id, lastBytesIn, lastBytesOut, e.error?.takeIf { it.isNotEmpty() })
        _state.update { it.copy(history = store.entries) }
    }

    private var lastBytesIn = 0L
    private var lastBytesOut = 0L
    private var accountName: String? = null

    private fun appendLog(line: String) {
        log.addLast(line)
        while (log.size > MAX_LOG_LINES) log.removeFirst()
        _state.update { it.copy(logLines = log.toList()) }
    }

    // endregion

    // region commands

    fun connect(server: VpnServer? = _state.value.selected) {
        if (server == null) return
        if (!requireAgreement { connect(server) }) return
        _state.update { it.copy(notice = null) }
        cancelReconnect()
        wanted = server
        reconnectAttempts = 0
        scope.launch { sendConnect(server) }
    }

    private suspend fun sendConnect(s: VpnServer) {
        val seq = ++connectSeq
        val sentAt = clock()
        _state.update { it.copy(state = ConnectionState.Connecting, server = s.ip, notice = null) }
        if (!permitted()) return
        accountName = null
        val request = ConnectRequest(
            host = s.ip,
            port = s.connectPort,
            ports = s.prioritizedSslPorts.takeIf { it.isNotEmpty() },
            proxy = settings.proxy.takeIf { it.kind != ProxyKind.None },
            // retrying is done here (considerReconnect), so the engine makes a single attempt
            autoReconnect = false,
            blockIPv6 = settings.blockIPv6,
        )
        settings.lastServer = request
        settings.lastAccountId = null
        ipc.connect(request)
        watchAnswer(seq, sentAt) { wanted?.id == s.id }
    }

    private suspend fun permitted(): Boolean {
        if (preparer.prepare()) return true
        wanted = null
        _state.update {
            it.copy(
                state = ConnectionState.Disconnected,
                notice = "VPN permission was not granted. Allow the VPN connection to continue.",
            )
        }
        appendLog("VPN permission denied")
        return false
    }

    /** An engine that never answers must not leave the UI on "Connecting…" forever. */
    private suspend fun watchAnswer(seq: Int, sentAt: Long, stillWanted: () -> Boolean) {
        delay(answerTimeoutMs)
        if (lastEventAt < sentAt && _state.value.state == ConnectionState.Connecting && seq == connectSeq && stillWanted()) {
            wanted = null
            accountWanted = null
            _state.update { it.copy(state = ConnectionState.Disconnected, notice = "The VPN engine is not responding.") }
            appendLog("No answer from the engine within ${answerTimeoutMs / 1000} s")
        }
    }

    // region accounts

    private var accountWanted: String? = null

    /** Connects with a saved connection setting; the engine retries by itself (the account's own reconnect settings). */
    fun connectAccount(account: ClientAccount) {
        val store = accountStore ?: return
        if (!requireAgreement { connectAccount(account) }) return
        _state.update { it.copy(notice = null) }
        cancelReconnect()
        wanted = null
        scope.launch {
            val seq = ++connectSeq
            val sentAt = clock()
            _state.update { it.copy(state = ConnectionState.Connecting, server = account.host, notice = null) }
            if (!permitted()) return@launch
            accountName = account.name
            accountWanted = account.id
            val request = store.connectRequest(account, settings.blockIPv6, settings.globalRouting)
            settings.lastAccountId = account.id
            settings.lastServer = null
            ipc.connect(request)
            watchAnswer(seq, sentAt) { accountWanted == account.id }
        }
    }

    /** Saves the editor form as a new account, or over [base]. */
    fun saveAccount(editor: AccountEditorState, base: ClientAccount?) {
        val store = accountStore ?: return
        val account = editor.makeAccount(base)
        val password = editor.password.takeIf { AuthTypes.usesPassword(editor.authType) }
        if (base == null) store.add(account, password, editor.certDer, editor.privateKeyDer)
        else store.update(account, password, editor.certDer, editor.privateKeyDer)
        refreshAccounts()
    }

    fun deleteAccount(account: ClientAccount) {
        accountStore?.delete(account)
        refreshAccounts()
    }

    fun duplicateAccount(account: ClientAccount) {
        accountStore?.duplicate(account)
        refreshAccounts()
    }

    /** The editor's starting state for [account] (null = a new one), with its stored secrets. */
    fun editorFor(account: ClientAccount?): AccountEditorState {
        val store = accountStore ?: return AccountEditorState()
        return if (account == null) AccountEditorState(proxy = settings.proxy.copy(password = null))
        else AccountEditorState(account, store.password(account), store.hasCertificateIdentity(account), store.proxyPassword(account))
    }

    private fun refreshAccounts() = _state.update {
        it.copy(accounts = accountStore?.accounts.orEmpty(), accountsNotice = accountStore?.loadNotice)
    }

    // endregion

    // region settings and history

    fun updateSettings(
        proxy: ProxySettings = settings.proxy,
        autoReconnect: Boolean = settings.autoReconnect,
        blockIPv6: Boolean = settings.blockIPv6,
        globalRouting: RoutingConfig = settings.globalRouting,
    ) {
        settings.proxy = proxy
        settings.autoReconnect = autoReconnect
        settings.blockIPv6 = blockIPv6
        settings.globalRouting = globalRouting
        _state.update {
            it.copy(proxy = proxy, autoReconnect = autoReconnect, blockIPv6 = blockIPv6, globalRouting = globalRouting)
        }
    }

    fun clearHistory() {
        historyStore?.clear()
        _state.update { it.copy(history = historyStore?.entries.orEmpty()) }
    }

    // endregion

    fun disconnect() {
        wanted = null
        accountWanted = null
        cancelReconnect()
        if (_state.value.state == ConnectionState.Reconnecting) _state.update { it.copy(state = ConnectionState.Disconnected) }
        ipc.disconnect()
    }

    /** The bottom button: Connect, Disconnect, or Cancel while busy. */
    fun act() {
        if (_state.value.state == ConnectionState.Disconnected) connect() else disconnect()
    }

    // endregion

    // region reconnect (list connections retry forever, every 15 s)

    private fun considerReconnect() {
        val server = wanted ?: return
        if (reconnectJob != null || !settings.autoReconnect) return
        reconnectAttempts++
        appendLog("Reconnecting to ${server.hostName} in ${(reconnectDelayMs + 999) / 1000} s (attempt $reconnectAttempts)")
        _state.update { it.copy(state = ConnectionState.Reconnecting, server = server.ip) }
        reconnectJob = scope.launch {
            delay(reconnectDelayMs)
            reconnectJob = null
            if (wanted?.id != server.id || _state.value.state != ConnectionState.Reconnecting) {
                if (_state.value.state == ConnectionState.Reconnecting) _state.update { it.copy(state = ConnectionState.Disconnected) }
                return@launch
            }
            sendConnect(server)
        }
    }

    private fun cancelReconnect() {
        reconnectJob?.cancel()
        reconnectJob = null
    }

    // endregion

    companion object {
        const val MAX_LOG_LINES = 300
    }
}
