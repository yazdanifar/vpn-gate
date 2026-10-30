package com.yazdanifar.vpngate.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
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
import com.yazdanifar.vpngate.RoutingAction
import com.yazdanifar.vpngate.RoutingConfig
import com.yazdanifar.vpngate.RoutingRule
import com.yazdanifar.vpngate.RoutingRuleType
import com.yazdanifar.vpngate.RoutingRuleValidation

private fun actionLabel(a: RoutingAction) = when (a) {
    RoutingAction.Proxy -> "Through VPN"
    RoutingAction.Direct -> "Bypass the VPN"
    RoutingAction.Block -> "Block"
}

/**
 * The routing rules (UI-SPEC 8): an ordered list (first match wins) with a default action and a private-network bypass.
 * The Android tunnel plan (`plan_for`) turns only "Direct" IPv4 IP and CIDR rules into excluded routes and the engine
 * refuses domain rules, so the editor offers just those ([com.yazdanifar.vpngate.RoutingConfig.forAndroid] enforces it).
 */
@Composable
fun RoutingEditor(config: RoutingConfig, onChange: (RoutingConfig) -> Unit) {
    var type by remember { mutableStateOf(RoutingRuleType.Cidr) }
    var value by remember { mutableStateOf("") }
    val error = if (value.isBlank()) null else RoutingRuleValidation.androidValueError(type, value)

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        SwitchRow(
            "Bypass private networks",
            config.bypassPrivateNetworks,
            { onChange(config.copy(bypassPrivateNetworks = it)) },
            hint = "Local addresses (10.x, 192.168.x, …) skip the VPN.",
        )
        Text(
            "Addresses and IPv4 ranges listed here skip the VPN. Domain rules and blocking are not available on Android.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        HorizontalDivider()
        Text("Bypass list", style = MaterialTheme.typography.titleSmall)
        config.rules.forEachIndexed { i, rule ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(rule.value)
                    Text(
                        RoutingRuleValidation.types.first { it.type == rule.type }.label,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(rule.enabled, { on -> onChange(config.copy(rules = config.rules.toMutableList().also { it[i] = rule.copy(enabled = on) })) })
                TextButton(enabled = i > 0, onClick = { onChange(config.copy(rules = config.rules.swap(i, i - 1))) }) { Text("↑") }
                TextButton(enabled = i < config.rules.size - 1, onClick = { onChange(config.copy(rules = config.rules.swap(i, i + 1))) }) { Text("↓") }
                TextButton(onClick = { onChange(config.copy(rules = config.rules.filterIndexed { j, _ -> j != i })) }) { Text("Remove") }
            }
        }
        Text("Add a rule", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp))
        Choice("Type", RoutingRuleValidation.androidTypes, RoutingRuleValidation.androidTypes.first { it.type == type }, { it.label }) { type = it.type }
        Field(
            "Value",
            value,
            { value = it },
            error = error,
            placeholder = RoutingRuleValidation.androidTypes.first { it.type == type }.placeholder,
        )
        Button(
            enabled = value.isNotBlank() && error == null,
            onClick = {
                onChange(config.copy(rules = config.rules + RoutingRule(type = type, value = value.trim(), action = RoutingAction.Direct)))
                value = ""
            },
        ) { Text("Add rule") }
    }
}

private fun <T> List<T>.swap(a: Int, b: Int): List<T> = toMutableList().also {
    val t = it[a]
    it[a] = it[b]
    it[b] = t
}
