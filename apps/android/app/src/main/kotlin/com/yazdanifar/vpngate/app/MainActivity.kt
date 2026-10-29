package com.yazdanifar.vpngate.app

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
                viewModel.onConsentResult(it.resultCode == RESULT_OK)
            }
            val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
            LaunchedEffect(Unit) {
                viewModel.consentLauncher = { consent.launch(it) }
                viewModel.model.start()
                // The foreground notification is what keeps the tunnel alive; without the permission it is only hidden.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
            }
            val state by viewModel.model.state.collectAsState()
            MainScreen(state, viewModel.model, onQuit = ::finishAndRemoveTask)
        }
    }

    override fun onDestroy() {
        viewModel.consentLauncher = null
        super.onDestroy()
    }
}
