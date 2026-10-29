package com.yazdanifar.vpngate.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.yazdanifar.vpngate.ConnectionState
import com.yazdanifar.vpngate.Fmt
import com.yazdanifar.vpngate.ListFormat
import com.yazdanifar.vpngate.MainModel
import com.yazdanifar.vpngate.ServerFilter
import com.yazdanifar.vpngate.SortKey
import com.yazdanifar.vpngate.UiState
import com.yazdanifar.vpngate.VpnServer

private val Green = Color(0xFF2E7D32)
private val Orange = Color(0xFFEF6C00)
private val Grey = Color(0xFF607D8B)

private const val DISCLAIMER_TITLE = "VPN Gate Academic Experiment Service"
private const val DISCLAIMER_BODY =
    "VPN Gate is an academic research project of the Graduate School of University of Tsukuba, Japan.\n\n" +
        "Public VPN relay servers are hosted by volunteers around the world. Anyone can connect through these servers " +
        "to achieve anonymity and bypass censorship.\n\n" +
        "By tapping “Agree and Continue”, you confirm that you will use this service in compliance with local laws."

@Composable
fun MainScreen(state: UiState, model: MainModel, onQuit: () -> Unit, onNavigate: (Screen) -> Unit) {
    if (state.showDisclaimer) {
        AlertDialog(
            onDismissRequest = {},
            title = { Text(DISCLAIMER_TITLE) },
            text = { Text(DISCLAIMER_BODY) },
            confirmButton = { TextButton(onClick = model::agree) { Text("Agree and Continue") } },
            dismissButton = {
                TextButton(onClick = {
                    model.disagree()
                    onQuit()
                }) { Text("Disagree & Quit") }
            },
        )
    }
    Scaffold(
        topBar = { MainBar(state, onNavigate) },
        bottomBar = { BottomBar(state, model) },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            ConnectionCard(state)
            Toolbar(state, model)
            Text(
                state.listStatus(System.currentTimeMillis()),
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                style = MaterialTheme.typography.bodySmall,
                color = if (state.listError != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            ServerList(state, model, Modifier.weight(1f))
        }
    }
}

@Composable
private fun ConnectionCard(state: UiState) {
    val color = when (state.state) {
        ConnectionState.Connected -> Green
        ConnectionState.Disconnected -> Grey
        else -> Orange
    }
    Card(
        Modifier.fillMaxWidth().padding(16.dp),
        colors = CardDefaults.cardColors(containerColor = color),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            val white = Color.White
            Text(
                if (state.state == ConnectionState.Disconnected) "Not connected" else state.stateTitle,
                style = MaterialTheme.typography.titleLarge,
                color = white,
            )
            if (state.state != ConnectionState.Disconnected) {
                val server = state.selected?.takeIf { it.ip == state.server }
                Text(
                    listOfNotNull(server?.flag?.takeIf { it.isNotEmpty() }, state.serverName).joinToString(" "),
                    color = white,
                )
                state.virtualIp?.let { Text("Virtual IP $it", color = white) }
            }
            if (state.state == ConnectionState.Connected) {
                Text(state.trafficText(System.currentTimeMillis()), color = white)
            } else if (state.state == ConnectionState.Disconnected) {
                Text(state.notice ?: "Select a server and press Connect.", color = white, maxLines = 3)
            }
        }
    }
}

@Composable
private fun Toolbar(state: UiState, model: MainModel) {
    Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = state.filter.search,
            onValueChange = model::setSearch,
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Search host, IP, country, operator") },
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            CountryMenu(state, model)
            FilterChip(
                selected = state.filter.favoritesOnly,
                onClick = { model.setFavoritesOnly(!state.filter.favoritesOnly) },
                label = { Text("Favorites") },
            )
            SortMenu(state, model)
            if (state.filter.isActive) TextButton(onClick = model::clearFilters) { Text("Clear") }
            Spacer(Modifier.weight(1f))
            TextButton(onClick = model::refreshList, enabled = !state.isLoading) { Text("Refresh") }
        }
    }
}

@Composable
private fun CountryMenu(state: UiState, model: MainModel) {
    var open by remember { mutableStateOf(false) }
    TextButton(onClick = { open = true }) {
        Text(if (state.filter.country == ServerFilter.ALL_COUNTRIES) "All countries" else state.filter.country)
    }
    DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
        DropdownMenuItem(text = { Text("All countries") }, onClick = {
            model.setCountry(ServerFilter.ALL_COUNTRIES)
            open = false
        })
        state.countries.forEach { c ->
            DropdownMenuItem(text = { Text(c) }, onClick = {
                model.setCountry(c)
                open = false
            })
        }
    }
}

@Composable
private fun SortMenu(state: UiState, model: MainModel) {
    var open by remember { mutableStateOf(false) }
    TextButton(onClick = { open = true }) { Text("Sort: ${sortLabel(state.sortKey)} ${if (state.sortDescending) "↓" else "↑"}") }
    DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
        SortKey.entries.forEach { k ->
            DropdownMenuItem(text = { Text(sortLabel(k)) }, onClick = {
                model.sortBy(k)
                open = false
            })
        }
    }
}

private fun sortLabel(k: SortKey) = when (k) {
    SortKey.Score -> "Score"
    SortKey.Host -> "Host"
    SortKey.Country -> "Region"
    SortKey.Uptime -> "Uptime"
    SortKey.Sessions -> "Sessions"
    SortKey.Speed -> "Speed"
    SortKey.Ping -> "Ping"
    SortKey.Logging -> "Logging"
}

@Composable
private fun ServerList(state: UiState, model: MainModel, modifier: Modifier) {
    LazyColumn(modifier) {
        items(state.servers, key = { it.id }) { s ->
            ServerRow(s, selected = s.id == state.selectedId, favorite = s.id in state.favorites, model = model)
            HorizontalDivider()
        }
    }
}

@Composable
private fun ServerRow(s: VpnServer, selected: Boolean, favorite: Boolean, model: MainModel) {
    val bg = if (selected) MaterialTheme.colorScheme.secondaryContainer else Color.Transparent
    Row(
        Modifier.fillMaxWidth().background(bg).clickable { model.select(s) }.padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text("${s.flag} ${s.countryLong}".trim(), fontWeight = FontWeight.Medium)
            Text("${s.ip} (${s.hostName})", style = MaterialTheme.typography.bodySmall)
            Text(
                "${Fmt.speed(s.speed)} · ${ListFormat.ping(s.ping)} · ${ListFormat.uptime(s.uptimeMs)} · " +
                    "${ListFormat.sessions(s.sessions.toLong())} · ${ListFormat.logging(s.logType)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Column(horizontalAlignment = Alignment.End) {
            Text("${s.score}", fontWeight = FontWeight.Bold)
            TextButton(onClick = { model.toggleFavorite(s) }) { Text(if (favorite) "★" else "☆") }
        }
    }
}

@Composable
private fun BottomBar(state: UiState, model: MainModel) {
    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        val disconnected = state.state == ConnectionState.Disconnected
        Button(
            onClick = model::act,
            enabled = !disconnected || state.canConnect,
            modifier = Modifier.fillMaxWidth(),
            colors = if (state.state == ConnectionState.Connected) {
                ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            } else {
                ButtonDefaults.buttonColors()
            },
        ) {
            Text(
                when (state.state) {
                    ConnectionState.Disconnected -> "Connect to the VPN Server"
                    ConnectionState.Connected -> "Disconnect"
                    else -> "Cancel"
                },
            )
        }
        Text(
            "Academic project at University of Tsukuba, Japan.",
            modifier = Modifier.padding(top = 8.dp),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
private fun MainBar(state: UiState, onNavigate: (Screen) -> Unit) {
    var open by remember { mutableStateOf(false) }
    androidx.compose.material3.TopAppBar(
        title = { Text("VPN Gate") },
        actions = {
            TextButton(onClick = { open = true }) { Text("Menu") }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                @Composable
                fun item(label: String, enabled: Boolean = true, to: Screen) =
                    DropdownMenuItem(text = { Text(label) }, enabled = enabled, onClick = {
                        open = false
                        onNavigate(to)
                    })
                item("Connection settings", to = Screen.Accounts)
                item("Server details", enabled = state.selected != null, to = Screen.Details)
                item("History", to = Screen.History)
                item("Log", to = Screen.Log)
                item("Settings", to = Screen.Settings)
            }
        },
    )
}
