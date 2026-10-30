package com.yazdanifar.vpngate.app

import android.content.Context
import com.yazdanifar.vpngate.ConnectRequest
import com.yazdanifar.vpngate.Ipc
import com.yazdanifar.vpngate.ProxySettings
import com.yazdanifar.vpngate.RoutingConfig
import com.yazdanifar.vpngate.SecretStore
import com.yazdanifar.vpngate.SettingsStore

/** [SettingsStore] over SharedPreferences, plus the last connect request for the always-on restart. */
class AppSettings(context: Context, private val secrets: SecretStore = KeystoreSecretStore(context)) : SettingsStore {
    private val prefs = context.applicationContext.getSharedPreferences("settings", Context.MODE_PRIVATE)

    override var hasAgreedToDisclaimer: Boolean
        get() = prefs.getBoolean("hasAgreedToDisclaimer", false)
        set(v) = prefs.edit().putBoolean("hasAgreedToDisclaimer", v).apply()

    override var favorites: Set<String>
        get() = prefs.getStringSet("favorites", emptySet()) ?: emptySet()
        set(v) = prefs.edit().putStringSet("favorites", v).apply()

    override var autoReconnect: Boolean
        get() = prefs.getBoolean("autoReconnect", true)
        set(v) = prefs.edit().putBoolean("autoReconnect", v).apply()

    override var blockIPv6: Boolean
        get() = prefs.getBoolean("blockIPv6", true)
        set(v) = prefs.edit().putBoolean("blockIPv6", v).apply()

    /** The proxy password is a secret: it lives in the Keystore-backed store, the rest in the preferences. */
    override var proxy: ProxySettings
        get() = prefs.getString("proxy", null)?.let {
            runCatching { Ipc.json.decodeFromString(ProxySettings.serializer(), it) }.getOrNull()
        }?.copy(password = secrets.get(PROXY_PASSWORD)) ?: ProxySettings()
        set(v) {
            prefs.edit().putString("proxy", Ipc.json.encodeToString(ProxySettings.serializer(), v.copy(password = null))).apply()
            if (v.password.isNullOrEmpty()) secrets.delete(PROXY_PASSWORD) else secrets.set(PROXY_PASSWORD, v.password!!)
        }

    override var globalRouting: RoutingConfig
        get() = prefs.getString("globalRouting", null)?.let {
            runCatching { Ipc.json.decodeFromString(RoutingConfig.serializer(), it) }.getOrNull()
        } ?: RoutingConfig()
        set(v) = prefs.edit().putString("globalRouting", Ipc.json.encodeToString(RoutingConfig.serializer(), v)).apply()

    override var lastAccountId: String?
        get() = prefs.getString("lastAccountId", null)
        set(v) = prefs.edit().apply { if (v == null) remove("lastAccountId") else putString("lastAccountId", v) }.apply()

    override var lastServer: ConnectRequest?
        get() = prefs.getString("lastServer", null)?.let {
            runCatching { Ipc.json.decodeFromString(ConnectRequest.serializer(), it) }.getOrNull()
        }
        set(v) = prefs.edit().apply {
            if (v == null) remove("lastServer") else putString("lastServer", Ipc.json.encodeToString(ConnectRequest.serializer(), v))
        }.apply()

    private companion object {
        const val PROXY_PASSWORD = "proxy-password"
    }
}
