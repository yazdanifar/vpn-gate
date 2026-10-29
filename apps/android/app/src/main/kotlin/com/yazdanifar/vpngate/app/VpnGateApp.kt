package com.yazdanifar.vpngate.app

import android.app.Application

class VpnGateApp : Application() {
    /** One engine per process; created on first use so a cold start into the UI stays cheap. */
    val hub: EngineHub by lazy { EngineHub(this) }
}
