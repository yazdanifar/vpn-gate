package com.yazdanifar.vpngate.app

import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import com.yazdanifar.vpngate.UiState
import org.junit.Rule
import org.junit.Test

/** The scrolling forms on a tall screen, so one golden shows the whole form. */
class TallScreenshotTest {
    @get:Rule
    val paparazzi = Paparazzi(deviceConfig = DeviceConfig.PIXEL_5.copy(screenHeight = 4200))

    private val model = Fixtures.model()

    @Test fun settings_default() = paparazzi.snapshot { SettingsScreen(UiState(), model) {} }

    @Test fun settings_proxy_and_routing() = paparazzi.snapshot {
        SettingsScreen(
            UiState(proxy = Fixtures.proxyHttp(), globalRouting = Fixtures.routing, autoReconnect = false, blockIPv6 = false),
            model,
        ) {}
    }

    @Test fun editor_new() = paparazzi.snapshot { WithNoActivity { AccountEditorScreen(model, null, { null }) {} } }

    @Test fun editor_edit_password_account() = paparazzi.snapshot {
        WithNoActivity { AccountEditorScreen(model, Fixtures.account, { null }) {} }
    }

    @Test fun editor_edit_certificate_account() = paparazzi.snapshot {
        WithNoActivity { AccountEditorScreen(model, Fixtures.certAccount, { null }) {} }
    }
}
