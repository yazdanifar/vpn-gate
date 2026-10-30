package com.yazdanifar.vpngate.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** The running [VpnEngineService], if any: the engine's threads call into it, the UI waits for it. */
object VpnBridge {
    private val _running = MutableStateFlow<VpnEngineService?>(null)
    val running: StateFlow<VpnEngineService?> = _running.asStateFlow()

    val service: VpnEngineService? get() = _running.value

    fun attach(service: VpnEngineService) {
        _running.value = service
    }

    fun detach(service: VpnEngineService) {
        if (_running.value === service) _running.value = null
    }
}
