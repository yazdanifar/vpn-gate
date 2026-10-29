package com.yazdanifar.vpngate.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.yazdanifar.vpngate.ConnectRequest
import com.yazdanifar.vpngate.Ipc
import com.yazdanifar.vpngate.RouteSplit
import uniffi.vpngate_uniffi.EstablishResult
import uniffi.vpngate_uniffi.TunnelPlanRecord
import java.net.InetAddress

/**
 * The system side of the tunnel. The Rust engine decides when a tunnel is needed: it calls [establish] with a plan and
 * reads and writes the returned descriptor itself. This service only builds the interface, shows the foreground
 * notification and protects sockets.
 *
 * Always-on VPN and "Block connections without VPN" start the service with the system's action and no extra data; the
 * service then reconnects to the server that was last used.
 */
class VpnEngineService : VpnService() {
    override fun onCreate() {
        super.onCreate()
        VpnBridge.attach(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundNow()
        when (intent?.action) {
            ACTION_STOP -> {
                (application as VpnGateApp).hub.send("""{"cmd":"disconnect"}""")
                stopSelf()
            }
            ACTION_START -> {} // the UI sends the connect request once the service is up
            else -> reconnectLastServer() // the system (always-on VPN) or a restart after the process was killed
        }
        return START_STICKY
    }

    override fun onRevoke() {
        // The user turned this VPN off in system settings or another VPN app took over.
        (application as VpnGateApp).hub.send("""{"cmd":"disconnect"}""")
        stopSelf()
    }

    override fun onDestroy() {
        VpnBridge.detach(this)
        super.onDestroy()
    }

    private fun reconnectLastServer() {
        val last = AppSettings(this).lastServer ?: return
        (application as VpnGateApp).hub.send(Ipc.json.encodeToString(ConnectRequest.serializer(), last))
    }

    /** Called on an engine thread. */
    fun establish(plan: TunnelPlanRecord): EstablishResult = try {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(plan.mtu.toInt())
            .addAddress(plan.address, plan.prefixLength.toInt())
            .setBlocking(true)
        val exclude = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        // Below API 33 there is no excludeRoute: the included routes are split around the excluded ones.
        val routes = if (exclude) plan.routes else RouteSplit.split(plan.routes, plan.excludedRoutes)
        for (r in routes) {
            val (addr, len) = r.split("/")
            builder.addRoute(addr, len.toInt())
        }
        if (exclude) {
            for (r in plan.excludedRoutes) {
                val (addr, len) = r.split("/")
                builder.excludeRoute(IpPrefix(InetAddress.getByName(addr), len.toInt()))
            }
        }
        // IPv6 enters the tunnel and is dropped there instead of leaking around it.
        if (plan.blockIpv6) builder.addRoute("::", 0)
        plan.dnsServers.forEach { builder.addDnsServer(it) }
        val pfd: ParcelFileDescriptor? = builder.establish()
        if (pfd == null) {
            EstablishResult(-1, "The VPN permission was revoked")
        } else {
            // The engine owns the descriptor from here on and closes it itself.
            EstablishResult(pfd.detachFd(), null)
        }
    } catch (e: Exception) {
        EstablishResult(-1, e.message ?: e.javaClass.simpleName)
    }

    /** Called on an engine thread when the engine closed the tunnel and no session is left. */
    fun onTunnelClosed() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun startForegroundNow() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW),
        )
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, VpnEngineService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        val n = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText("VPN is active")
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Disconnect", stop).build())
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }

    companion object {
        const val ACTION_START = "com.yazdanifar.vpngate.START"
        const val ACTION_STOP = "com.yazdanifar.vpngate.STOP"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION_ID = 1

        fun start(context: Context) {
            context.startForegroundService(Intent(context, VpnEngineService::class.java).setAction(ACTION_START))
        }
    }
}
