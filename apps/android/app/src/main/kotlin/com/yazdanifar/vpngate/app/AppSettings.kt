package com.yazdanifar.vpngate.app

import android.content.Context
import com.yazdanifar.vpngate.ConnectRequest
import com.yazdanifar.vpngate.Ipc
import com.yazdanifar.vpngate.SettingsStore

/** [SettingsStore] over SharedPreferences, plus the last connect request for the always-on restart. */
class AppSettings(context: Context) : SettingsStore {
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

    override var lastServer: ConnectRequest?
        get() = prefs.getString("lastServer", null)?.let {
            runCatching { Ipc.json.decodeFromString(ConnectRequest.serializer(), it) }.getOrNull()
        }
        set(v) = prefs.edit().apply {
            if (v == null) remove("lastServer") else putString("lastServer", Ipc.json.encodeToString(ConnectRequest.serializer(), v))
        }.apply()
}
