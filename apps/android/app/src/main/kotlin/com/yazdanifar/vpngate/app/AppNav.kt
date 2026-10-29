package com.yazdanifar.vpngate.app

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import com.yazdanifar.vpngate.ClientAccount
import com.yazdanifar.vpngate.MainModel
import com.yazdanifar.vpngate.UiState

enum class Screen { Main, Accounts, Editor, Details, History, Log, Settings }

/** A tiny back stack of one: every screen but the main one returns to where it was opened (the editor to the list). */
@Composable
fun AppRoot(state: UiState, model: MainModel, readUri: (Uri) -> ByteArray?, onQuit: () -> Unit) {
    var screen by rememberSaveable { mutableStateOf(Screen.Main) }
    var editing by rememberSaveable { mutableStateOf<String?>(null) }

    fun back() {
        screen = if (screen == Screen.Editor) Screen.Accounts else Screen.Main
    }
    BackHandler(enabled = screen != Screen.Main) { back() }

    when (screen) {
        Screen.Main -> MainScreen(state, model, onQuit) { screen = it }
        Screen.Accounts -> AccountsScreen(state, model, onBack = ::back) { account: ClientAccount? ->
            editing = account?.id
            screen = Screen.Editor
        }
        Screen.Editor -> AccountEditorScreen(model, state.accounts.firstOrNull { it.id == editing }, readUri, onClose = ::back)
        Screen.Details -> state.selected?.let { ServerDetailsScreen(it, onBack = ::back) } ?: MainScreen(state, model, onQuit) { screen = it }
        Screen.History -> HistoryScreen(state, model, onBack = ::back)
        Screen.Log -> LogScreen(state, onBack = ::back)
        Screen.Settings -> SettingsScreen(state, model, onBack = ::back)
    }
}
