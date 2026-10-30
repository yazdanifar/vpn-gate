package com.yazdanifar.vpngate.app

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.unit.dp
import com.yazdanifar.vpngate.AccountEditorState
import com.yazdanifar.vpngate.AuthTypes
import com.yazdanifar.vpngate.CertImport
import com.yazdanifar.vpngate.InputValidation
import com.yazdanifar.vpngate.CertImportException
import com.yazdanifar.vpngate.ClientAccount
import com.yazdanifar.vpngate.ConnectionState
import com.yazdanifar.vpngate.MainModel
import com.yazdanifar.vpngate.ProxyKind
import com.yazdanifar.vpngate.ProxySettings
import com.yazdanifar.vpngate.UiState

@Composable
fun AccountsScreen(
    state: UiState,
    model: MainModel,
    onBack: () -> Unit,
    onEdit: (ClientAccount?) -> Unit,
) {
    var deleting by remember { mutableStateOf<ClientAccount?>(null) }
    Scaffold(topBar = { ScreenBar("Connection settings", onBack) { TextButton(onClick = { onEdit(null) }) { Text("New") } } }) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            state.accountsNotice?.let {
                Text(it, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            if (state.accounts.isEmpty()) {
                Text("No saved connections. Tap New to add your own SoftEther server.", Modifier.padding(16.dp))
            }
            LazyColumn {
                items(state.accounts, key = { it.id }) { a ->
                    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                        Text(a.name, style = MaterialTheme.typography.titleMedium)
                        Text("${a.host}:${a.portList.joinToString("/")} · ${a.hub}", style = MaterialTheme.typography.bodySmall)
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            Button(
                                enabled = state.state == ConnectionState.Disconnected,
                                onClick = {
                                    model.connectAccount(a)
                                    onBack()
                                },
                            ) { Text("Connect") }
                            TextButton(onClick = { onEdit(a) }) { Text("Edit") }
                            TextButton(onClick = { model.duplicateAccount(a) }) { Text("Duplicate") }
                            TextButton(onClick = { deleting = a }) { Text("Delete") }
                        }
                    }
                    HorizontalDivider()
                }
            }
        }
    }
    deleting?.let { a ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text("Delete “${a.name}”?") },
            text = { Text("The saved password and certificate are removed too.") },
            confirmButton = {
                TextButton(onClick = {
                    model.deleteAccount(a)
                    deleting = null
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text("Cancel") } },
        )
    }
}

@Composable
fun AccountEditorScreen(
    model: MainModel,
    account: ClientAccount?,
    readUri: (Uri) -> ByteArray?,
    onClose: () -> Unit,
) {
    var s by remember { mutableStateOf(model.editorFor(account)) }
    var p12Pass by remember { mutableStateOf("") }
    var advanced by remember { mutableStateOf(false) }

    fun import(uri: Uri, block: (ByteArray) -> AccountEditorState) {
        val data = readUri(uri)
        s = if (data == null) s.copy(importError = "That file could not be read.") else try {
            block(data).copy(importError = null)
        } catch (e: CertImportException) {
            s.copy(importError = e.message)
        }
    }

    // After both halves are in, check that they belong together.
    fun checked(next: AccountEditorState): AccountEditorState {
        val c = next.certDer
        val k = next.privateKeyDer
        if (c == null || k == null) return next
        CertImport.pair(c, k)
        return next
    }

    val pickCert = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) import(uri) { checked(s.copy(certDer = CertImport.parseCertificate(it))) }
    }
    val pickKey = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) import(uri) { checked(s.copy(privateKeyDer = CertImport.parsePrivateKey(it))) }
    }
    val pickP12 = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) import(uri) {
            val id = CertImport.parsePkcs12(it, p12Pass)
            s.copy(certDer = id.certDer, privateKeyDer = id.privateKeyDer)
        }
    }

    Scaffold(
        topBar = {
            ScreenBar(if (account == null) "New connection" else "Edit connection", onClose) {
                TextButton(
                    enabled = s.canSave,
                    onClick = {
                        model.saveAccount(s, account)
                        onClose()
                    },
                ) { Text("Save") }
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding).padding(horizontal = 16.dp).verticalScroll(rememberScrollState())) {
            Field("Name", s.name, { s = s.copy(name = it) })
            Field("Server", s.host, { s = s.copy(host = it) }, error = if (s.host.isNotBlank() && !InputValidation.isValidHost(s.host.trim())) "Not a valid host name or IPv4 address." else null)
            Field("Ports", s.portString, { s = s.copy(portString = it) }, placeholder = "443, 992, 5555, 1194")
            Field("Virtual hub", s.hub, { s = s.copy(hub = it) })
            Field("User name", s.username, { s = s.copy(username = it) })
            Choice("Authentication", AuthTypes.all, s.authType, { it }) { s = s.copy(authType = it) }
            if (AuthTypes.usesPassword(s.authType)) {
                Field("Password", s.password, { s = s.copy(password = it) }, secret = true)
            }
            if (s.authType == AuthTypes.CERTIFICATE) {
                Section("Certificate") {
                    Text(
                        when {
                            s.certDer != null && s.privateKeyDer != null -> "A new certificate and key are ready."
                            s.hasStoredIdentity -> "A certificate and key are stored. Import files to replace them."
                            else -> "Import a certificate and its RSA key, or a .p12 file."
                        },
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { pickCert.launch(arrayOf("*/*")) }) { Text("Certificate…") }
                        OutlinedButton(onClick = { pickKey.launch(arrayOf("*/*")) }) { Text("Private key…") }
                    }
                    Field("PKCS#12 passphrase", p12Pass, { p12Pass = it }, secret = true)
                    OutlinedButton(onClick = { pickP12.launch(arrayOf("*/*")) }) { Text(".p12 file…") }
                    s.importError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                }
            }
            Section("Connection") {
                SwitchRow("UDP acceleration", s.udpAcceleration, { s = s.copy(udpAcceleration = it) })
                SwitchRow("Compression", s.compression, { s = s.copy(compression = it) })
                SwitchRow("Quality of service", s.useQoS, { s = s.copy(useQoS = it) })
                SwitchRow("Half connection", s.halfConnection, { s = s.copy(halfConnection = it) })
                SwitchRow("Reconnect automatically", s.autoReconnect, { s = s.copy(autoReconnect = it) })
                Field("Parallel connections (1–32)", s.maxConnection.toString(), { s = s.copy(maxConnection = it.toIntOrNull() ?: 1) })
            }
            Section("Server certificate") {
                SwitchRow("Check the server certificate", s.checkServerCert, { s = s.copy(checkServerCert = it) })
                Field("Fingerprint (SHA-1 or SHA-256)", s.fingerprint, { s = s.copy(fingerprint = it) }, error = s.fingerprintError ?: s.trustError)
            }
            Section("Proxy") { ProxyFields(s.proxy) { s = s.copy(proxy = it) } }
            Section("Advanced") {
                TextButton(onClick = { advanced = !advanced }) { Text(if (advanced) "Hide advanced" else "Show advanced") }
                if (advanced || s.advancedInvalid) {
                    Field("MTU (blank = automatic)", s.mtuString, { s = s.copy(mtuString = it) }, error = s.mtuError)
                    Field("Virtual MAC (blank = random)", s.macString, { s = s.copy(macString = it) }, error = s.macError)
                    Field("Reconnect interval (s)", s.reconnectIntervalSeconds.toString(), { s = s.copy(reconnectIntervalSeconds = it.toIntOrNull() ?: 1) })
                    Field("Reconnect attempts", s.reconnectCount.toString(), { s = s.copy(reconnectCount = it.toIntOrNull() ?: 1) })
                }
            }
            Section("Routing") {
                SwitchRow("Use rules of my own for this connection", s.useCustomRouting, { s = s.copy(useCustomRouting = it) },
                    hint = "Off: the rules from Settings apply.")
                if (s.useCustomRouting) RoutingEditor(s.routing) { s = s.copy(routing = it) }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** The proxy form shared by the account editor and Settings. SOCKS5 *mode* is not offered on Android (DECISIONS U27). */
@Composable
fun ProxyFields(proxy: ProxySettings, onChange: (ProxySettings) -> Unit) {
    Choice("Proxy", ProxyKind.entries, proxy.kind, {
        when (it) {
            ProxyKind.None -> "None"
            ProxyKind.Http -> "HTTP"
            ProxyKind.Socks5 -> "SOCKS5"
        }
    }) { onChange(proxy.copy(kind = it)) }
    if (proxy.kind != ProxyKind.None) {
        Field("Proxy host", proxy.host, { onChange(proxy.copy(host = it)) })
        Field("Proxy port", if (proxy.port == 0) "" else proxy.port.toString(), { onChange(proxy.copy(port = it.toIntOrNull() ?: 0)) })
        Field("Proxy user name (optional)", proxy.username.orEmpty(), { onChange(proxy.copy(username = it.ifEmpty { null })) })
        Field("Proxy password (optional)", proxy.password.orEmpty(), { onChange(proxy.copy(password = it.ifEmpty { null })) }, secret = true)
    }
}
