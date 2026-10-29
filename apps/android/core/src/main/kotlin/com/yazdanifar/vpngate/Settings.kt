package com.yazdanifar.vpngate

/** What the UI remembers between runs; the app backs it with SharedPreferences, tests with memory. */
interface SettingsStore {
    var hasAgreedToDisclaimer: Boolean
    var favorites: Set<String>
    var autoReconnect: Boolean
    var blockIPv6: Boolean

    /** Proxy for list connections and list downloads; the app keeps its password in the secret store. */
    var proxy: ProxySettings

    /** Rules applied to accounts that have none of their own. */
    var globalRouting: RoutingConfig

    /** The last connect request, replayed when the system starts the always-on VPN. */
    var lastServer: ConnectRequest?

    /** Set instead of [lastServer] when the last connection was an account. */
    var lastAccountId: String?
}

class MemorySettings(
    override var hasAgreedToDisclaimer: Boolean = false,
    override var favorites: Set<String> = emptySet(),
    override var autoReconnect: Boolean = true,
    override var blockIPv6: Boolean = true,
    override var proxy: ProxySettings = ProxySettings(),
    override var globalRouting: RoutingConfig = RoutingConfig(),
    override var lastServer: ConnectRequest? = null,
    override var lastAccountId: String? = null,
) : SettingsStore
