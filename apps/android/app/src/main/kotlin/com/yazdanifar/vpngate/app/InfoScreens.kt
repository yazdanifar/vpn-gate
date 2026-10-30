package com.yazdanifar.vpngate.app

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.yazdanifar.vpngate.Fmt
import com.yazdanifar.vpngate.ListFormat
import com.yazdanifar.vpngate.MainModel
import com.yazdanifar.vpngate.UiState
import com.yazdanifar.vpngate.VpnServer
import java.text.DateFormat
import java.util.Date

@Composable
fun SettingsScreen(state: UiState, model: MainModel, onBack: () -> Unit) {
    Scaffold(topBar = { ScreenBar("Settings", onBack) }) { padding ->
        Column(Modifier.padding(padding).padding(horizontal = 16.dp).verticalScroll(rememberScrollState())) {
            Section("General") {
                SwitchRow(
                    "Reconnect automatically",
                    state.autoReconnect,
                    { model.updateSettings(autoReconnect = it) },
                    hint = "Servers from the list are retried every 15 s.",
                )
                SwitchRow(
                    "Block IPv6",
                    state.blockIPv6,
                    { model.updateSettings(blockIPv6 = it) },
                    hint = "Keeps IPv6 traffic from leaking around the tunnel.",
                )
            }
            Section("Proxy for the list and public servers") {
                ProxyFields(state.proxy) { model.updateSettings(proxy = it) }
            }
            Section("Routing") {
                Text(
                    "Applies to connections without rules of their own.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                RoutingEditor(state.globalRouting) { model.updateSettings(globalRouting = it) }
            }
            Section("Always-on VPN") {
                Text("Turn on “Always-on VPN” and “Block connections without VPN” for VPN Gate in the system VPN settings.")
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
fun HistoryScreen(state: UiState, model: MainModel, onBack: () -> Unit) {
    val fmt = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
    Scaffold(topBar = {
        ScreenBar("History", onBack) { TextButton(enabled = state.history.isNotEmpty(), onClick = model::clearHistory) { Text("Clear") } }
    }) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            if (state.history.isEmpty()) Text("No connections yet.", Modifier.padding(16.dp))
            LazyColumn {
                items(state.history, key = { it.id }) { e ->
                    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                        Text("${e.serverName} (${e.serverIp})", style = MaterialTheme.typography.titleSmall)
                        Text(fmt.format(Date(e.connectedAtMs)), style = MaterialTheme.typography.bodySmall)
                        Text(
                            e.durationSeconds?.let { "${Fmt.duration(it.toLong())} · ↓ ${Fmt.bytes(e.bytesIn)} ↑ ${Fmt.bytes(e.bytesOut)}" }
                                ?: "Still connected or interrupted",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        e.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    }
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
fun LogScreen(state: UiState, onBack: () -> Unit) {
    Scaffold(topBar = { ScreenBar("Log", onBack) }) { padding ->
        LazyColumn(Modifier.padding(padding).padding(horizontal = 16.dp).fillMaxSize()) {
            if (state.logLines.isEmpty()) item { Text("Nothing logged yet.") }
            items(state.logLines) { Text(it, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

@Composable
fun ServerDetailsScreen(server: VpnServer, onBack: () -> Unit) {
    val rows = listOf(
        "Host name" to server.hostName,
        "IP address" to server.ip,
        "Country" to "${server.flag} ${server.countryLong}".trim(),
        "Score" to server.score.toString(),
        "Speed" to Fmt.speed(server.speed),
        "Ping" to ListFormat.ping(server.ping),
        "Uptime" to ListFormat.uptime(server.uptimeMs),
        "Sessions" to ListFormat.sessions(server.sessions.toLong()),
        "Total users" to server.totalUsers.toString(),
        "Total traffic" to Fmt.bytes(server.totalTraffic),
        "Logging" to ListFormat.logging(server.logType),
        "Operator" to server.operatorName,
        "Message" to server.message,
        "SSL ports" to server.sslPorts.joinToString(", "),
        "UDP port" to (server.udpPort?.toString() ?: ""),
        "Software" to listOfNotNull(server.soft, server.build?.toString()).joinToString(" "),
        "OS" to (server.os ?: ""),
        "Owner" to (server.owner ?: ""),
        "Abuse contact" to (server.abuse ?: ""),
    ).filter { it.second.isNotBlank() }
    Scaffold(topBar = { ScreenBar("Server details", onBack) }) { padding ->
        Column(Modifier.padding(padding).padding(horizontal = 16.dp).verticalScroll(rememberScrollState())) {
            rows.forEach { (k, v) ->
                Text(k, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 8.dp))
                Text(v)
            }
        }
    }
}
