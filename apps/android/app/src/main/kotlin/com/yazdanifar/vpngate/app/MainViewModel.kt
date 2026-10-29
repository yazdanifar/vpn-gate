package com.yazdanifar.vpngate.app

import android.app.Application
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.yazdanifar.vpngate.IpcClient
import com.yazdanifar.vpngate.MainModel
import com.yazdanifar.vpngate.VpnPreparer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull

/** Hosts [MainModel] across configuration changes and implements the Android half of "prepare the VPN". */
class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val hub = (app as VpnGateApp).hub
    private val ipc = IpcClient(hub, viewModelScope)

    /** Set by the activity while it is resumed: shows the system consent dialog. */
    var consentLauncher: ((Intent) -> Unit)? = null
    private var consent: CompletableDeferred<Boolean>? = null

    val model = MainModel(
        ipc = ipc,
        settings = AppSettings(app),
        scope = viewModelScope,
        preparer = VpnPreparer { prepare() },
    )

    fun onConsentResult(granted: Boolean) {
        consent?.complete(granted)
    }

    private suspend fun prepare(): Boolean {
        val app = getApplication<Application>()
        val intent = VpnService.prepare(app)
        if (intent != null) {
            val answer = CompletableDeferred<Boolean>().also { consent = it }
            val launch = consentLauncher ?: return false
            launch(intent)
            if (!answer.await()) return false
        }
        VpnEngineService.start(app)
        // The engine asks the service for the tunnel as soon as it connects, so the service must be attached first.
        return withTimeoutOrNull(5_000) { VpnBridge.running.first { it != null } } != null
    }
}
