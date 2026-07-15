package com.xcj.app

import android.app.Application
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Inventory
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.QueryStats
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.xcj.app.data.prefs.TokenStore
import com.xcj.app.ui.CardsTab
import com.xcj.app.ui.LoginScreen
import com.xcj.app.ui.PackHelperTab
import com.xcj.app.ui.StatsTab
import com.xcj.app.vm.CardsViewModel
import com.xcj.app.vm.LoginViewModel
import com.xcj.app.vm.StatsViewModel
import timber.log.Timber

/**
 * 小城笺管理 APP
 *
 * v2 重构后:
 *  - 登录页(无 token 时显示)
 *  - 卡密管理 Tab(调 /apps/{appId}/cards)
 *  - 打包辅助 Tab(替代原 APK 注入 Tab,引导开发者主动集成 SDK)
 *  - 统计 Tab(调 /developer/stats/overview)
 *
 * 服务器 URL 由 build.gradle.kts 的 buildConfigField 注入,不硬编码。
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val store = TokenStore(this)

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val token = store.accessToken

                    if (token.isNullOrBlank()) {
                        val loginVm: LoginViewModel = viewModel(factory = loginVmFactory(store))
                        LoginScreen(
                            viewModel = loginVm,
                            onSuccess = { recreate() }, // 切换到主屏
                        )
                    } else {
                        MainScaffold(store)
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScaffold(store: TokenStore) {
    var tab by remember { mutableIntStateOf(0) }

    val cardsVm: CardsViewModel = viewModel(factory = cardsVmFactory(store))
    val statsVm: StatsViewModel = viewModel(factory = statsVmFactory(store))

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("小城笺管理") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            PrimaryTabRow(selectedTabIndex = tab) {
                Tab(
                    selected = tab == 0,
                    onClick = { tab = 0 },
                    text = { Text("卡密管理") },
                    icon = { Icon(Icons.Default.Key, contentDescription = null) },
                )
                Tab(
                    selected = tab == 1,
                    onClick = { tab = 1 },
                    text = { Text("打包辅助") },
                    icon = { Icon(Icons.Default.Inventory, contentDescription = null) },
                )
                Tab(
                    selected = tab == 2,
                    onClick = { tab = 2 },
                    text = { Text("统计") },
                    icon = { Icon(Icons.Default.QueryStats, contentDescription = null) },
                )
            }
            when (tab) {
                0 -> CardsTab(viewModel = cardsVm)
                1 -> PackHelperTab()
                2 -> StatsTab(viewModel = statsVm)
            }
        }
    }
}

// ---------- ViewModel 工厂 ----------

private fun loginVmFactory(store: TokenStore) = viewModelFactory {
    initializer { LoginViewModel(store = store) }
}

private fun cardsVmFactory(store: TokenStore) = viewModelFactory {
    initializer { CardsViewModel(store = store) }
}

private fun statsVmFactory(store: TokenStore) = viewModelFactory {
    initializer { StatsViewModel(store = store) }
}

/**
 * Application 初始化 Timber
 */
class XcjApp : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }
    }
}
