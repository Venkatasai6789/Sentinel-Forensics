package com.deepfakeshield.feature.vault

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.deepfakeshield.core.security.DeviceAuthHelper
import com.deepfakeshield.core.ui.components.ClinicalEmptyState
import com.deepfakeshield.core.ui.components.ClinicalSurfaceCard
import com.deepfakeshield.core.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val TabularNoteStyle = TextStyle(fontFeatureSettings = "tnum")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecureNotesScreen(
    viewModel: SecureNotesViewModel = hiltViewModel(),
    onNavigateBack: () -> Unit = {}
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }

    val noteCategories = listOf("General", "Recovery Key", "Incident Log", "Credentials", "Device Note")
    var searchQuery by remember { mutableStateOf("") }
    var selectedFilter by remember { mutableIntStateOf(0) }
    val filters = listOf("All", "Pinned") + noteCategories

    var showEditor by remember { mutableStateOf(false) }
    var editingNote by remember { mutableStateOf<DecryptedSecureNote?>(null) }
    var editorTitle by remember { mutableStateOf("") }
    var editorContent by remember { mutableStateOf("") }
    var editorCategoryIdx by remember { mutableIntStateOf(0) }
    var deleteConfirmId by remember { mutableStateOf<Long?>(null) }

    LaunchedEffect(uiState.statusMessage) {
        uiState.statusMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.clearMessage()
        }
    }

    LaunchedEffect(uiState.error) {
        uiState.error?.let {
            snackbar.showSnackbar(it)
            viewModel.clearMessage()
        }
    }

    deleteConfirmId?.let { id ->
        AlertDialog(
            onDismissRequest = { deleteConfirmId = null },
            containerColor = SurfaceLight,
            titleContentColor = TextPrimary,
            textContentColor = TextSecondary,
            title = { Text("Delete Encrypted Note", fontWeight = FontWeight.SemiBold) },
            text = { Text("This permanently removes the AES-256-GCM ciphertext entry from your local vault.") },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.deleteNote(id)
                        deleteConfirmId = null
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = DangerRed, contentColor = Color.White)
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteConfirmId = null }) { Text("Cancel") }
            }
        )
    }

    if (showEditor) {
        val noteFieldStyle = com.deepfakeshield.core.ui.components.clinicalTextFieldStyle()
        val noteFieldColors = com.deepfakeshield.core.ui.components.clinicalOutlinedTextFieldColors()
        AlertDialog(
            onDismissRequest = { showEditor = false },
            containerColor = SurfaceLight,
            titleContentColor = TextPrimary,
            textContentColor = TextSecondary,
            title = { Text(if (editingNote == null) "New Encrypted Note" else "Edit Encrypted Note", fontWeight = FontWeight.SemiBold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = editorTitle,
                        onValueChange = { editorTitle = it },
                        label = { Text("Title") },
                        singleLine = true,
                        textStyle = noteFieldStyle,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth(),
                        colors = noteFieldColors
                    )
                    OutlinedTextField(
                        value = editorContent,
                        onValueChange = { editorContent = it },
                        label = { Text("Sensitive content (encrypted at rest)") },
                        minLines = 4,
                        maxLines = 8,
                        textStyle = noteFieldStyle,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth(),
                        colors = noteFieldColors
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        noteCategories.forEachIndexed { idx, cat ->
                            FilterChip(
                                selected = editorCategoryIdx == idx,
                                onClick = { editorCategoryIdx = idx },
                                label = { Text(cat, fontSize = 11.sp) }
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.saveNote(
                            id = editingNote?.id,
                            title = editorTitle,
                            content = editorContent,
                            category = noteCategories[editorCategoryIdx],
                            isPinned = editingNote?.isPinned ?: false
                        )
                        showEditor = false
                    },
                    enabled = editorTitle.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = SentinelPrimary,
                        contentColor = Color.White,
                        disabledContainerColor = SurfaceSubtle,
                        disabledContentColor = TextTertiary
                    )
                ) {
                    Text("Encrypt & Save")
                }
            },
            dismissButton = {
                TextButton(onClick = { showEditor = false }) { Text("Cancel") }
            }
        )
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Text("Secure Notes", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                            Text("Android Keystore AES-256-GCM Room Storage", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                        }
                    },
                    navigationIcon = {
                        IconButton(onClick = onNavigateBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        if (uiState.isUnlocked) {
                            IconButton(onClick = { viewModel.lockNotes() }) {
                                Icon(Icons.Filled.Lock, contentDescription = "Lock Notes", tint = TextPrimary)
                            }
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = SurfaceLight)
                )
                HorizontalDivider(color = BorderColor)
            }
        },
        floatingActionButton = {
            if (uiState.isUnlocked) {
                FloatingActionButton(
                    onClick = {
                        editingNote = null
                        editorTitle = ""
                        editorContent = ""
                        editorCategoryIdx = 0
                        showEditor = true
                    },
                    containerColor = SentinelPrimary,
                    contentColor = Color.White
                ) {
                    Icon(Icons.Filled.Add, contentDescription = "New Encrypted Note")
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = BackgroundLight
    ) { padding ->
        if (!uiState.isUnlocked) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 20.dp, vertical = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                ClinicalSurfaceCard {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                        Box(
                            modifier = Modifier
                                .size(48.dp)
                                .background(SentinelPrimaryContainer, CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Outlined.Lock, contentDescription = null, tint = SentinelPrimary, modifier = Modifier.size(24.dp))
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Encrypted Notes Locked", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                            Text(
                                text = "${uiState.noteMetadata.size} encrypted note(s) stored in Room. Authenticate to decrypt note bodies.",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextSecondary
                            )
                        }
                    }

                    Spacer(Modifier.height(14.dp))

                    if (uiState.biometricStatus == DeviceAuthHelper.BiometricStatus.NOT_ENROLLED) {
                        Surface(color = WarningContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                            Text(
                                text = "Configure a screen lock, PIN, or biometric in Android Settings to unlock encrypted notes.",
                                modifier = Modifier.padding(10.dp),
                                fontSize = 12.sp,
                                color = WarningAmber
                            )
                        }
                    } else {
                        Button(
                            onClick = { viewModel.authenticate(context) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(50.dp),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary, contentColor = Color.White)
                        ) {
                            Icon(Icons.Filled.Fingerprint, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Unlock with Biometric / PIN", fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        } else {
            val filteredNotes = remember(uiState.notes, searchQuery, selectedFilter) {
                uiState.notes
                    .filter { note ->
                        when (selectedFilter) {
                            0 -> true
                            1 -> note.isPinned
                            else -> note.category == filters[selectedFilter]
                        }
                    }
                    .filter { note ->
                        searchQuery.isBlank() ||
                            note.title.contains(searchQuery, ignoreCase = true) ||
                            note.content.contains(searchQuery, ignoreCase = true)
                    }
                    .sortedWith(compareByDescending<DecryptedSecureNote> { it.isPinned }.thenByDescending { it.createdAt })
            }

            val dateFmt = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item {
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        textStyle = com.deepfakeshield.core.ui.components.clinicalTextFieldStyle(),
                        placeholder = { Text("Search decrypted notes...") },
                        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                        trailingIcon = {
                            if (searchQuery.isNotEmpty()) {
                                IconButton(onClick = { searchQuery = "" }) {
                                    Icon(Icons.Filled.Close, contentDescription = "Clear", tint = TextSecondary)
                                }
                            }
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        colors = com.deepfakeshield.core.ui.components.clinicalOutlinedTextFieldColors(
                            focusedContainerColor = SurfaceLight,
                            unfocusedContainerColor = SurfaceLight
                        )
                    )
                }

                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        filters.forEachIndexed { idx, label ->
                            FilterChip(
                                selected = selectedFilter == idx,
                                onClick = { selectedFilter = idx },
                                label = { Text(label, fontSize = 12.sp) }
                            )
                        }
                    }
                }

                if (filteredNotes.isEmpty()) {
                    item {
                        ClinicalEmptyState(
                            icon = Icons.Outlined.Description,
                            title = if (uiState.notes.isEmpty()) "No Encrypted Notes Yet" else "No Matching Notes",
                            description = if (uiState.notes.isEmpty()) {
                                "Tap + to encrypt and store recovery keys or incident notes locally using Android Keystore AES-256-GCM."
                            } else {
                                "No notes match the current filter or search query."
                            }
                        )
                    }
                } else {
                    items(filteredNotes, key = { it.id }) { note ->
                        ClinicalSurfaceCard {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        if (note.isPinned) {
                                            Icon(Icons.Filled.PushPin, contentDescription = "Pinned", modifier = Modifier.size(14.dp), tint = SentinelPrimary)
                                        }
                                        Text(note.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                                    }
                                    Text(
                                        text = "${note.category} • ${dateFmt.format(Date(note.createdAt))} • ${note.charCount} chars",
                                        style = TabularNoteStyle.copy(fontSize = 11.sp),
                                        color = TextSecondary
                                    )
                                }
                                Row {
                                    IconButton(onClick = { viewModel.togglePin(note) }) {
                                        Icon(
                                            imageVector = if (note.isPinned) Icons.Filled.PushPin else Icons.Outlined.PushPin,
                                            contentDescription = "Pin",
                                            tint = if (note.isPinned) SentinelPrimary else TextSecondary
                                        )
                                    }
                                    IconButton(onClick = { viewModel.copyNoteToClipboard(note) }) {
                                        Icon(Icons.Filled.ContentCopy, contentDescription = "Copy", tint = TextSecondary)
                                    }
                                    IconButton(
                                        onClick = {
                                            editingNote = note
                                            editorTitle = note.title
                                            editorContent = note.content
                                            editorCategoryIdx = noteCategories.indexOf(note.category).coerceAtLeast(0)
                                            showEditor = true
                                        }
                                    ) {
                                        Icon(Icons.Filled.Edit, contentDescription = "Edit", tint = SentinelPrimary)
                                    }
                                    IconButton(onClick = { deleteConfirmId = note.id }) {
                                        Icon(Icons.Filled.DeleteOutline, contentDescription = "Delete", tint = DangerRed)
                                    }
                                }
                            }
                            Spacer(Modifier.height(8.dp))
                            Surface(color = SurfaceSubtle, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                                Text(
                                    text = note.content,
                                    modifier = Modifier.padding(10.dp),
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 12.sp,
                                    color = TextPrimary,
                                    maxLines = 6,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
