package com.yazdanifar.vpngate.app

import android.Manifest
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.lifecycle.ViewModelProvider
import androidx.test.rule.GrantPermissionRule
import com.yazdanifar.vpngate.MainModel
import com.yazdanifar.vpngate.ServerFilter
import com.yazdanifar.vpngate.app.Harness.eventually
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * An open dropdown must survive what the screen receives while the user is choosing: a list refresh and a Test run
 * (a state update per relay). The desktop Country/Filter menus once closed whenever the window was rebuilt; this is the
 * same check on Android, on the real app with the bundled list.
 */
class FilterMenuTest {
    @get:Rule(order = 0)
    val permission: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS)

    @get:Rule(order = 1)
    val compose = createAndroidComposeRule<MainActivity>()

    private fun hasNodes(text: String, substring: Boolean = false) =
        runCatching { compose.onAllNodes(hasText(text, substring = substring)).fetchSemanticsNodes().isNotEmpty() }.getOrDefault(false)

    @Test
    fun countryMenuStaysOpenWhileTheListRefreshesAndTestRuns() {
        Harness.resetAppState()
        eventually(90_000, "the disclaimer or the list") { hasNodes("Agree and Continue") || hasNodes("Public VPN Relay Servers on the Earth!", true) }
        if (hasNodes("Agree and Continue")) compose.onNodeWithText("Agree and Continue").performClick()
        eventually(90_000, "the bundled list") { hasNodes("Public VPN Relay Servers on the Earth!", true) }

        lateinit var model: MainModel
        compose.activityRule.scenario.onActivity { model = ViewModelProvider(it)[MainViewModel::class.java].model }
        eventually(30_000, "the countries") { model.state.value.countries.isNotEmpty() }
        val country = model.state.value.countries.first()

        // Open the Country menu: the button and the menu's own "All countries" entry are both on screen.
        compose.onAllNodesWithText("All countries").onFirst().performClick()
        eventually(10_000, "the Country menu") { compose.onAllNodesWithText("All countries").fetchSemanticsNodes().size >= 2 }
        eventually(10_000, "the first country in the menu") { hasNodes(country) }

        // What used to close menus: a refresh and a Test run, each publishing state.
        compose.runOnUiThread {
            model.refreshList()
            model.testConnections()
        }
        eventually(10_000, "Test to start") { model.state.value.isTesting || model.state.value.isLoading }
        val end = System.currentTimeMillis() + 4_000
        while (System.currentTimeMillis() < end) {
            assertTrue(
                "the Country menu closed while the list refreshed / Test ran (state: testing=${model.state.value.isTesting})",
                compose.onAllNodesWithText("All countries").fetchSemanticsNodes().size >= 2 && hasNodes(country),
            )
            Thread.sleep(250)
        }

        // Choosing still works.
        compose.onAllNodesWithText(country).onFirst().performClick()
        eventually(10_000, "the country filter") { model.state.value.filter.country == country }
        assertEquals(country, model.state.value.filter.country)
        assertTrue(model.state.value.filter.country != ServerFilter.ALL_COUNTRIES)
    }
}
