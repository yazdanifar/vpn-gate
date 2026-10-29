package com.yazdanifar.vpngate

/** What the UI remembers between runs; the app backs it with SharedPreferences, tests with memory. */
interface SettingsStore {
    var hasAgreedToDisclaimer: Boolean
    var favorites: Set<String>
    var autoReconnect: Boolean
    var blockIPv6: Boolean

    /** The last connect request, replayed when the system starts the always-on VPN. */
    var lastServer: ConnectRequest?
}

class MemorySettings(
    override var hasAgreedToDisclaimer: Boolean = false,
    override var favorites: Set<String> = emptySet(),
    override var autoReconnect: Boolean = true,
    override var blockIPv6: Boolean = true,
    override var lastServer: ConnectRequest? = null,
) : SettingsStore
