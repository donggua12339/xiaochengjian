package com.xcj.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.MenuAnchorType
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.xcj.app.data.model.CardKeyDto
import com.xcj.app.vm.CardsViewModel
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * 卡密管理 Tab
 *
 * - 顶部应用下拉选择
 * - 卡密列表(LazyColumn)
 * - 每条卡密提供 禁用/启用 + 解绑 操作
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CardsTab(viewModel: CardsViewModel) {
    val state by viewModel.state.collectAsState()
    var menuExpanded by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("卡密管理", style = MaterialTheme.typography.headlineSmall)

        ExposedDropdownMenuBox(
            expanded = menuExpanded,
            onExpandedChange = { menuExpanded = it },
        ) {
            OutlinedTextField(
                value = state.currentApp?.name ?: "请选择应用",
                onValueChange = {},
                readOnly = true,
                label = { Text("当前应用") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = menuExpanded) },
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor(MenuAnchorType.PrimaryNotEditable, true),
            )
            DropdownMenu(
                expanded = menuExpanded,
                onDismissRequest = { menuExpanded = false },
            ) {
                state.apps.forEach { app ->
                    DropdownMenuItem(
                        text = { Text("${app.name} (${app.id.take(8)})") },
                        onClick = {
                            viewModel.selectApp(app.id)
                            menuExpanded = false
                        },
                    )
                }
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "共 ${state.total} 条",
                style = MaterialTheme.typography.bodyMedium,
            )
            Button(onClick = { viewModel.refresh() }) {
                Icon(Icons.Default.Refresh, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("刷新")
            }
        }

        when {
            state.loading && state.cards.isEmpty() -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                ) {
                    CircularProgressIndicator()
                }
            }
            state.error != null -> Text(
                state.error!!,
                color = MaterialTheme.colorScheme.error,
            )
            state.cards.isEmpty() -> Text(
                "暂无卡密,请在 Web 后台生成",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            else -> LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(state.cards, key = { it.id }) { card ->
                    CardItem(
                        card = card,
                        onDisable = { viewModel.disable(card.id) },
                        onEnable = { viewModel.enable(card.id) },
                        onUnbind = { viewModel.unbind(card.id) },
                    )
                }
            }
        }

        state.message?.let {
            Card {
                Text(it, modifier = Modifier.padding(12.dp))
            }
        }
    }
}

@Composable
private fun CardItem(
    card: CardKeyDto,
    onDisable: () -> Unit,
    onEnable: () -> Unit,
    onUnbind: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AssistChip(onClick = {}, label = { Text(card.status) })
                AssistChip(onClick = {}, label = { Text(card.type) })
                AssistChip(onClick = {}, label = { Text(card.bindingStrategy) })
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "卡密前缀:${card.cardKeyPrefix}${card.mask?.let { "  $it" } ?: ""}",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                "创建:${formatTime(card.createdAt)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            card.activatedAt?.let {
                Text(
                    "激活:${formatTime(it)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            card.expiresAt?.let {
                Text(
                    "到期:${formatTime(it)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (card.status == "ACTIVE") {
                    TextButton(onClick = onDisable) { Text("禁用") }
                } else {
                    TextButton(onClick = onEnable) { Text("启用") }
                }
                TextButton(onClick = onUnbind) { Text("解绑设备") }
            }
        }
    }
}

private val TIME_FMT: DateTimeFormatter = DateTimeFormatter
    .ofPattern("yyyy-MM-dd HH:mm")
    .withZone(ZoneId.systemDefault())

private fun formatTime(iso: String): String = runCatching {
    TIME_FMT.format(Instant.parse(iso))
}.getOrElse { iso }
