package com.yazdanifar.vpngate.app

import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import com.yazdanifar.vpngate.UiState
import org.junit.Rule
import org.junit.Test

/**
 * Golden screenshots of the Compose screens (src/test/snapshots). `verifyPaparazziDebug` diffs against them,
 * `recordPaparazziDebug` rewrites them; CI produces the reference images (docs/cross-platform/PLATFORMS.md).
 * Dropdown menus and dialogs are separate windows that this Paparazzi version does not draw; the emulator tests cover them.
 */
class ScreenshotTest {
    @get:Rule
    val paparazzi = Paparazzi(deviceConfig = DeviceConfig.PIXEL_5)

    private val model = Fixtures.model()
    private val noop = {}

    @Test fun main_list() = paparazzi.snapshot { MainScreen(Fixtures.base, model, noop) {} }

    @Test fun main_connected() = paparazzi.snapshot { MainScreen(Fixtures.connected, model, noop) {} }

    @Test fun main_connecting() = paparazzi.snapshot { MainScreen(Fixtures.connecting, model, noop) {} }

    @Test fun main_filtered_by_search() = paparazzi.snapshot {
        val base = Fixtures.base
        MainScreen(base.copy(filter = base.filter.copy(search = "kr", favoritesOnly = true)), model, noop) {}
    }

    @Test fun main_empty_list_error() = paparazzi.snapshot {
        MainScreen(UiState(listError = "no relay answered"), model, noop) {}
    }

    @Test fun main_refreshing_first_run() = paparazzi.snapshot { MainScreen(UiState(isLoading = true), model, noop) {} }

    @Test fun disclaimer() = paparazzi.snapshot { MainScreen(Fixtures.base.copy(showDisclaimer = true), model, noop) {} }

    @Test fun server_details() = paparazzi.snapshot { ServerDetailsScreen(Fixtures.servers[0]) {} }

    @Test fun accounts_empty() = paparazzi.snapshot { AccountsScreen(UiState(), model, onBack = {}) {} }

    @Test fun accounts_list() = paparazzi.snapshot {
        AccountsScreen(UiState(accounts = listOf(Fixtures.account, Fixtures.certAccount)), model, onBack = {}) {}
    }

    @Test fun accounts_notice() = paparazzi.snapshot {
        AccountsScreen(
            UiState(accounts = listOf(Fixtures.account), accountsNotice = "1 saved connection setting(s) could not be read and were skipped."),
            model, onBack = {},
        ) {}
    }

    @Test fun history_empty() = paparazzi.snapshot { HistoryScreen(UiState(), model) {} }

    @Test fun history_list() = paparazzi.snapshot { HistoryScreen(UiState(history = Fixtures.history), model) {} }

    @Test fun log_empty() = paparazzi.snapshot { LogScreen(UiState()) {} }

    @Test fun log_lines() = paparazzi.snapshot {
        LogScreen(
            UiState(
                logLines = listOf(
                    "Connecting to public-vpn-231 (219.100.37.231)",
                    "TLS established on port 443",
                    "Authenticated as vpn (anonymous)",
                    "Address 10.21.0.17/16 from DHCP",
                    "Connected",
                ),
            ),
        ) {}
    }
}
