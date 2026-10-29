package com.yazdanifar.vpngate.app

import android.content.Context
import com.yazdanifar.vpngate.EngineChannel
import uniffi.vpngate_uniffi.AndroidEngine
import uniffi.vpngate_uniffi.EstablishResult
import uniffi.vpngate_uniffi.LineListener
import uniffi.vpngate_uniffi.TunnelPlanRecord
import uniffi.vpngate_uniffi.VpnHostCallbacks
import java.io.File

/**
 * Owns the Rust engine of this process and adapts it to [EngineChannel]. The engine calls back into
 * [VpnBridge.service] to create the tunnel and to protect its sockets.
 */
class EngineHub(context: Context) : EngineChannel {
    override var listener: ((String) -> Unit)? = null

    private val engine: AndroidEngine

    init {
        val files = context.filesDir
        engine = AndroidEngine(
            files.absolutePath,
            copyBundledList(context, files),
            Host,
            object : LineListener {
                override fun onLine(line: String) {
                    listener?.invoke(line)
                }
            },
        )
    }

    override fun send(requestJson: String) = engine.send(requestJson)

    fun shutdown() = engine.shutdown()

    private object Host : VpnHostCallbacks {
        override fun establish(plan: TunnelPlanRecord): EstablishResult {
            val service = VpnBridge.service
                ?: return EstablishResult(-1, "The VPN service is not running")
            return service.establish(plan)
        }

        // Without a running VpnService there is no tunnel to keep the socket out of.
        override fun protect(fd: Int): Boolean = VpnBridge.service?.protect(fd) ?: true

        override fun tunnelClosed() {
            VpnBridge.service?.onTunnelClosed()
        }
    }

    private companion object {
        /** The shipped VPNGate.dat is an APK asset; the engine reads plain files. */
        fun copyBundledList(context: Context, dir: File): String? = try {
            val out = File(dir, "VPNGate.bundle.dat")
            context.assets.open("VPNGate.dat").use { input -> out.outputStream().use { input.copyTo(it) } }
            out.absolutePath
        } catch (_: java.io.IOException) {
            null
        }
    }
}
