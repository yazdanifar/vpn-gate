package com.yazdanifar.vpngate.app

import android.app.Application
import com.yazdanifar.vpngate.AccountStore
import com.yazdanifar.vpngate.ConnectionHistoryStore
import java.io.File

class VpnGateApp : Application() {
    /** One engine per process; created on first use so a cold start into the UI stays cheap. */
    val hub: EngineHub by lazy { EngineHub(this) }

    /** Shared by the UI and the service (the always-on start replays the last account). */
    val secrets by lazy { KeystoreSecretStore(this) }
    val accounts by lazy { AccountStore(File(filesDir, "accounts.json"), secrets) }
    val history by lazy { ConnectionHistoryStore(File(filesDir, "connection_history.json")) }
}
