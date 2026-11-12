package com.deepfakeshield.feature.onboarding

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel

// Authoritative Design Tokens from DESIGN.md
private val ColorPrimary = Color(0xFF4F72E8)
private val ColorPrimaryPressed = Color(0xFF3F60CF)
private val ColorPrimaryContainer = Color(0xFFE9EEFF)
private val ColorOnPrimary = Color(0xFFFFFFFF)

private val ColorBackground = Color(0xFFF5F6F8)
private val ColorSurface = Color(0xFFFFFFFF)
private val ColorSurfaceSubtle = Color(0xFFF2F4F7)
private val ColorSurfaceSelected = Color(0xFFEEF1FF)
private val ColorBorder = Color(0xFFE6E9EF)
private val ColorBorderSelected = Color(0xFF4F72E8)

private val ColorTextPrimary = Color(0xFF17191F)
private val ColorTextSecondary = Color(0xFF747B87)
private val ColorTextTertiary = Color(0xFF969DA8)

private val ColorSuccess = Color(0xFF25A653)
private val ColorSuccessContainer = Color(0xFFE8F7ED)
private val ColorDanger = Color(0xFFC83E4D)

/**
 * Sentinel Forensics Security Personalisation Screen.
 *
 * Implements a clean, trustworthy digital forensics aesthetic strictly adhering to DESIGN.md:
 * - Clear typographic hierarchy and calm, neutral surface separation
 * - Interactive multi-selection with accessible semantics and immediate visual updates
 * - Live selection counter ("X of 8 selected") with progress visualization
 * - Minimum 3 selections requirement to enable primary action
 * - Honest, functional "Skip for now" path with safe state preservation
 * - Fully adapted for India region exclusively (USA and manual location selector eliminated)
 * - Safe scrollable layout respecting status and navigation system bars
 */
@Composable
fun PersonalizationScreen(
    onComplete: (Set<String>, String) -> Unit,
    viewModel: PersonalizationViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val haptic = LocalHapticFeedback.current

    PersonalizationContent(
        uiState = uiState,
        onToggleCategory = { category ->
            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
            viewModel.toggleCategory(category)
        },
        onContinue = {
            viewModel.continueToNextScreen(onComplete)
        },
        onSkip = {
            viewModel.skipForNow(onComplete)
        }
    )
}

@Composable
fun PersonalizationContent(
    uiState: SecurityPreferencesUiState,
    onToggleCategory: (SecurityCategory) -> Unit,
    onContinue: () -> Unit,
    onSkip: () -> Unit,
    modifier: Modifier = Modifier
) {
    val categories = remember { SecurityCategory.values() }
    val scrollState = rememberScrollState()

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = ColorBackground,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        bottomBar = {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = ColorSurface,
                shadowElevation = 8.dp,
                border = BorderStroke(1.dp, ColorBorder)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .windowInsetsPadding(WindowInsets.navigationBars)
                        .padding(horizontal = 20.dp, vertical = 14.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Helper or Error Text
                    val helperText = when {
                        uiState.errorMessage != null -> uiState.errorMessage
                        !uiState.canContinue -> "Select at least 3 areas to continue."
                        else -> "${uiState.selectedCount} areas selected • Ready to continue"
                    }
                    val helperColor = when {
                        uiState.errorMessage != null -> ColorDanger
                        !uiState.canContinue -> ColorTextSecondary
                        else -> ColorSuccess
                    }

                    Text(
                        text = helperText,
                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 13.sp),
                        color = helperColor,
                        fontWeight = if (uiState.canContinue) FontWeight.SemiBold else FontWeight.Normal,
                        textAlign = TextAlign.Center
                    )

                    // Primary Button
                    Button(
                        onClick = onContinue,
                        enabled = uiState.canContinue,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(54.dp),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = ColorPrimary,
                            contentColor = ColorOnPrimary,
                            disabledContainerColor = ColorBorder,
                            disabledContentColor = ColorTextTertiary
                        ),
                        elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp)
                    ) {
                        if (uiState.isSaving) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = ColorOnPrimary,
                                strokeWidth = 2.dp
                            )
                            Spacer(Modifier.width(10.dp))
                            Text(
                                text = "Saving preferences...",
                                style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold)
                            )
                        } else {
                            Text(
                                text = if (uiState.selectedCount >= 3) {
                                    "Continue (${uiState.selectedCount} selected)"
                                } else {
                                    "Continue"
                                },
                                style = MaterialTheme.typography.labelLarge.copy(
                                    fontWeight = FontWeight.SemiBold,
                                    fontSize = 16.sp
                                )
                            )
                        }
                    }

                    // Secondary Action: Skip for now
                    TextButton(
                        onClick = onSkip,
                        enabled = !uiState.isSaving,
                        modifier = Modifier.height(40.dp)
                    ) {
                        Text(
                            text = "Skip for now",
                            style = MaterialTheme.typography.bodyMedium.copy(
                                fontWeight = FontWeight.Medium,
                                fontSize = 14.sp
                            ),
                            color = ColorTextSecondary
                        )
                    }
                }
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(scrollState)
                .windowInsetsPadding(WindowInsets.statusBars)
                .padding(horizontal = 20.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header Hero Icon
            Box(
                modifier = Modifier
                    .size(68.dp)
                    .clip(CircleShape)
                    .background(ColorPrimaryContainer)
                    .border(BorderStroke(1.dp, Color(0xFFD4DFFB)), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Outlined.Shield,
                    contentDescription = null,
                    modifier = Modifier.size(34.dp),
                    tint = ColorPrimary
                )
            }

            // Eyebrow & Title & Subtitle
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = "PERSONALISE YOUR PROTECTION",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.2.sp
                    ),
                    color = ColorPrimary
                )

                Text(
                    text = "What matters most to you?",
                    style = MaterialTheme.typography.headlineSmall.copy(
                        fontWeight = FontWeight.Bold,
                        fontSize = 24.sp,
                        lineHeight = 30.sp
                    ),
                    color = ColorTextPrimary,
                    textAlign = TextAlign.Center
                )

                Text(
                    text = "Choose the security areas you want to focus on. You can change these preferences anytime in Settings.",
                    style = MaterialTheme.typography.bodyMedium.copy(
                        fontSize = 14.sp,
                        lineHeight = 20.sp
                    ),
                    color = ColorTextSecondary,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 8.dp)
                )
            }

            // Live Progress Metric Card
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = ColorSurface,
                border = BorderStroke(1.dp, ColorBorder)
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(20.dp)
                                    .clip(CircleShape)
                                    .background(
                                        if (uiState.selectedCount >= 3) ColorSuccessContainer
                                        else ColorPrimaryContainer
                                    ),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = if (uiState.selectedCount >= 3) Icons.Outlined.Check
                                    else Icons.Outlined.Security,
                                    contentDescription = null,
                                    modifier = Modifier.size(12.dp),
                                    tint = if (uiState.selectedCount >= 3) ColorSuccess else ColorPrimary
                                )
                            }

                            Text(
                                text = "${uiState.selectedCount} of ${categories.size} selected",
                                style = MaterialTheme.typography.labelMedium.copy(
                                    fontWeight = FontWeight.SemiBold,
                                    fontSize = 13.sp
                                ),
                                color = ColorTextPrimary
                            )
                        }

                        Text(
                            text = if (uiState.selectedCount >= 3) "Requirement met" else "Select at least 3",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontWeight = FontWeight.Medium,
                                fontSize = 12.sp
                            ),
                            color = if (uiState.selectedCount >= 3) ColorSuccess else ColorTextSecondary
                        )
                    }

                    LinearProgressIndicator(
                        progress = { (uiState.selectedCount / categories.size.toFloat()).coerceIn(0f, 1f) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp)
                            .clip(RoundedCornerShape(3.dp)),
                        color = if (uiState.selectedCount >= 3) ColorSuccess else ColorPrimary,
                        trackColor = ColorBorder,
                        strokeCap = StrokeCap.Round
                    )
                }
            }

            // 8 Categories Multi-Selection List
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                categories.forEach { category ->
                    val isSelected = category in uiState.selectedCategories
                    SecurityCategoryRow(
                        category = category,
                        isSelected = isSelected,
                        onClick = { onToggleCategory(category) }
                    )
                }
            }

            // Bottom Spacing to ensure comfortable scrolling above bottom bar
            Spacer(Modifier.height(12.dp))
        }
    }
}

/**
 * Individual Multi-Selectable Security Category Row.
 * Uses DESIGN.md tokens: radius.md (14 dp), clear surface contrast, accessible selection semantics.
 */
@Composable
fun SecurityCategoryRow(
    category: SecurityCategory,
    isSelected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .selectable(
                selected = isSelected,
                role = Role.Checkbox,
                onClick = onClick
            ),
        color = if (isSelected) ColorSurfaceSelected else ColorSurface,
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(
            width = if (isSelected) 1.5.dp else 1.dp,
            color = if (isSelected) ColorBorderSelected else ColorBorder
        ),
        tonalElevation = if (isSelected) 0.dp else 1.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Category Leading Icon in styled container
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(
                        if (isSelected) ColorPrimaryContainer else ColorSurfaceSubtle
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = category.icon,
                    contentDescription = null,
                    modifier = Modifier.size(22.dp),
                    tint = if (isSelected) ColorPrimary else ColorTextSecondary
                )
            }

            Spacer(Modifier.width(14.dp))

            // Title and Description
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(3.dp)
            ) {
                Text(
                    text = category.title,
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 15.sp
                    ),
                    color = ColorTextPrimary
                )

                Text(
                    text = category.description,
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontSize = 12.5.sp,
                        lineHeight = 17.sp
                    ),
                    color = ColorTextSecondary
                )
            }

            Spacer(Modifier.width(12.dp))

            // Trailing Selection Indicator
            Box(
                modifier = Modifier
                    .size(24.dp)
                    .clip(CircleShape)
                    .background(if (isSelected) ColorPrimary else Color.Transparent)
                    .border(
                        width = if (isSelected) 0.dp else 1.5.dp,
                        color = if (isSelected) Color.Transparent else Color(0xFFD4D8E2),
                        shape = CircleShape
                    ),
                contentAlignment = Alignment.Center
            ) {
                if (isSelected) {
                    Icon(
                        imageVector = Icons.Default.Check,
                        contentDescription = "Selected",
                        tint = Color.White,
                        modifier = Modifier.size(15.dp)
                    )
                }
            }
        }
    }
}

@Preview(name = "1. Personalisation - Initial State", showBackground = true, widthDp = 390, heightDp = 1020)
@Composable
fun PersonalizationScreenInitialPreview() {
    MaterialTheme {
        PersonalizationContent(
            uiState = SecurityPreferencesUiState(
                selectedCategories = emptySet(),
                countryCode = "IN"
            ),
            onToggleCategory = {},
            onContinue = {},
            onSkip = {}
        )
    }
}

@Preview(name = "2. Personalisation - 3 Selected (Ready to Continue)", showBackground = true, widthDp = 390, heightDp = 1020)
@Composable
fun PersonalizationScreenSelectedPreview() {
    MaterialTheme {
        PersonalizationContent(
            uiState = SecurityPreferencesUiState(
                selectedCategories = setOf(
                    SecurityCategory.SCAM_MESSAGE,
                    SecurityCategory.DEEPFAKE,
                    SecurityCategory.PHOTO_FORENSICS
                ),
                countryCode = "IN"
            ),
            onToggleCategory = {},
            onContinue = {},
            onSkip = {}
        )
    }
}

@Preview(name = "3. Personalisation - Standard Phone View", showBackground = true, widthDp = 390, heightDp = 844)
@Composable
fun PersonalizationScreenPhonePreview() {
    MaterialTheme {
        PersonalizationContent(
            uiState = SecurityPreferencesUiState(
                selectedCategories = setOf(
                    SecurityCategory.SCAM_MESSAGE,
                    SecurityCategory.DEEPFAKE,
                    SecurityCategory.PHOTO_FORENSICS
                ),
                countryCode = "IN"
            ),
            onToggleCategory = {},
            onContinue = {},
            onSkip = {}
        )
    }
}
