package com.deepfakeshield.core.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.TextSelectionColors
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ExpandLess
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.deepfakeshield.core.model.FindingSeverity
import com.deepfakeshield.core.model.ScanProgressState
import com.deepfakeshield.core.model.SecurityFinding
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.core.ui.theme.*

/**
 * Standard elevated-flat white forensic card (DESIGN.md).
 */
@Composable
fun ClinicalSurfaceCard(
    modifier: Modifier = Modifier,
    containerColor: Color = SurfaceLight,
    borderColor: Color = BorderColor,
    contentPadding: PaddingValues = PaddingValues(18.dp),
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    val cardModifier = if (onClick != null) {
        modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .clickable(onClick = onClick)
    } else {
        modifier.fillMaxWidth()
    }
    Card(
        modifier = cardModifier,
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        border = BorderStroke(1.dp, borderColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(modifier = Modifier.padding(contentPadding), content = content)
    }
}

@Composable
fun SectionHeaderRow(
    title: String,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    actionLabel: String? = null,
    onActionClick: (() -> Unit)? = null
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = TextPrimary
            )
            if (!subtitle.isNullOrBlank()) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary
                )
            }
        }
        if (!actionLabel.isNullOrBlank() && onActionClick != null) {
            TextButton(
                onClick = onActionClick,
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = actionLabel,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = SentinelPrimary
                )
            }
        }
    }
}

data class VerdictVisualStyle(
    val containerColor: Color,
    val contentColor: Color,
    val borderColor: Color
)

fun verdictStyle(verdict: SecurityVerdict): VerdictVisualStyle = when (verdict) {
    SecurityVerdict.SAFE,
    SecurityVerdict.LIKELY_AUTHENTIC -> VerdictVisualStyle(
        containerColor = SuccessContainer,
        contentColor = SuccessGreen,
        borderColor = SuccessGreen.copy(alpha = 0.25f)
    )
    SecurityVerdict.LOW_RISK -> VerdictVisualStyle(
        containerColor = SentinelPrimaryContainer,
        contentColor = SentinelPrimary,
        borderColor = SentinelPrimary.copy(alpha = 0.25f)
    )
    SecurityVerdict.SUSPICIOUS -> VerdictVisualStyle(
        containerColor = WarningContainer,
        contentColor = WarningAmber,
        borderColor = WarningAmber.copy(alpha = 0.25f)
    )
    SecurityVerdict.HIGH_RISK,
    SecurityVerdict.MALICIOUS,
    SecurityVerdict.LIKELY_AI_GENERATED -> VerdictVisualStyle(
        containerColor = DangerContainer,
        contentColor = DangerRed,
        borderColor = DangerRed.copy(alpha = 0.25f)
    )
    SecurityVerdict.INCONCLUSIVE,
    SecurityVerdict.NOT_SUPPORTED,
    SecurityVerdict.NOT_ANALYZED -> VerdictVisualStyle(
        containerColor = SurfaceSubtle,
        contentColor = TextSecondary,
        borderColor = BorderColor
    )
}

fun findingSeverityStyle(severity: FindingSeverity): VerdictVisualStyle = when (severity) {
    FindingSeverity.INFO -> VerdictVisualStyle(SurfaceSubtle, TextSecondary, BorderColor)
    FindingSeverity.LOW -> VerdictVisualStyle(SentinelPrimaryContainer, SentinelPrimary, SentinelPrimary.copy(alpha = 0.25f))
    FindingSeverity.MEDIUM -> VerdictVisualStyle(WarningContainer, WarningAmber, WarningAmber.copy(alpha = 0.25f))
    FindingSeverity.HIGH, FindingSeverity.CRITICAL -> VerdictVisualStyle(DangerContainer, DangerRed, DangerRed.copy(alpha = 0.25f))
}

@Composable
fun VerdictStatusPill(
    verdict: SecurityVerdict,
    modifier: Modifier = Modifier
) {
    val style = verdictStyle(verdict)
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(999.dp),
        color = style.containerColor,
        border = BorderStroke(1.dp, style.borderColor)
    ) {
        Text(
            text = verdict.label,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = style.contentColor
        )
    }
}

/**
 * Genuine stage-based progress panel tied to actual pipeline steps (DESIGN.md Scan progress).
 */
@Composable
fun ForensicStageProgressCard(
    progressState: ScanProgressState.Running,
    onCancel: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    ClinicalSurfaceCard(modifier = modifier) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = progressState.stageTitle,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
                if (progressState.detail.isNotBlank()) {
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = progressState.detail,
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            if (progressState.totalSteps > 0) {
                Spacer(Modifier.width(12.dp))
                Text(
                    text = "${progressState.completedSteps}/${progressState.totalSteps}",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = SentinelPrimary
                )
            }
        }
        Spacer(Modifier.height(12.dp))
        if (progressState.totalSteps > 0) {
            val fraction = (progressState.completedSteps.toFloat() / progressState.totalSteps.toFloat()).coerceIn(0f, 1f)
            LinearProgressIndicator(
                progress = { fraction },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .clip(RoundedCornerShape(3.dp)),
                color = SentinelPrimary,
                trackColor = SurfaceSubtle
            )
        } else {
            LinearProgressIndicator(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .clip(RoundedCornerShape(3.dp)),
                color = SentinelPrimary,
                trackColor = SurfaceSubtle
            )
        }
        if (onCancel != null) {
            Spacer(Modifier.height(10.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = onCancel) {
                    Text("Cancel Scan", color = DangerRed, fontWeight = FontWeight.Medium)
                }
            }
        }
    }
}

@Composable
fun FindingEvidenceRow(
    finding: SecurityFinding,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }
    val sevStyle = findingSeverityStyle(finding.severity)

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .clickable { expanded = !expanded },
        shape = RoundedCornerShape(12.dp),
        color = SurfaceLight,
        border = BorderStroke(1.dp, BorderColor)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = sevStyle.containerColor,
                    border = BorderStroke(1.dp, sevStyle.borderColor)
                ) {
                    Text(
                        text = finding.severity.label,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = sevStyle.contentColor
                    )
                }
                Spacer(Modifier.width(10.dp))
                Text(
                    text = finding.title,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Icon(
                    imageVector = if (expanded) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore,
                    contentDescription = if (expanded) "Collapse" else "Expand",
                    tint = TextSecondary,
                    modifier = Modifier.size(20.dp)
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                text = finding.description,
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary
            )
            if (expanded) {
                Spacer(Modifier.height(10.dp))
                HorizontalDivider(color = BorderColor)
                Spacer(Modifier.height(10.dp))
                EvidenceMetaLine("Detection method", finding.detectionMethod)
                EvidenceMetaLine("Evidence source", finding.evidenceSource)
                if (!finding.inputLocation.isNullOrBlank()) {
                    EvidenceMetaLine("Matched location", finding.inputLocation)
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "Recommended action: ${finding.recommendedAction}",
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium,
                    color = TextPrimary
                )
            }
        }
    }
}

@Composable
private fun EvidenceMetaLine(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(
            text = "$label:",
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            color = TextSecondary
        )
        Text(
            text = value,
            fontSize = 12.sp,
            color = TextPrimary,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
fun LimitationDisclosureCard(
    methods: List<String>,
    limitations: List<String>,
    modifier: Modifier = Modifier
) {
    ClinicalSurfaceCard(
        modifier = modifier,
        containerColor = SurfaceSubtle,
        borderColor = BorderColor,
        contentPadding = PaddingValues(14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(Icons.Outlined.Info, contentDescription = null, tint = TextSecondary, modifier = Modifier.size(18.dp))
            Text(
                text = "Methods & Scope Disclosures",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = TextPrimary
            )
        }
        if (methods.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(
                text = "What was checked:",
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = TextSecondary
            )
            methods.forEach { method ->
                Text(
                    text = "- $method",
                    fontSize = 12.sp,
                    color = TextPrimary,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        }
        if (limitations.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(
                text = "Limitations / what could not be checked:",
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = TextSecondary
            )
            limitations.forEach { limit ->
                Text(
                    text = "- $limit",
                    fontSize = 12.sp,
                    color = TextSecondary,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        }
    }
}

@Composable
fun ClinicalMetricCard(
    label: String,
    value: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    accentColor: Color = SentinelPrimary,
    onClick: (() -> Unit)? = null
) {
    ClinicalSurfaceCard(
        modifier = modifier,
        contentPadding = PaddingValues(12.dp),
        onClick = onClick
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .background(accentColor.copy(alpha = 0.1f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(icon, contentDescription = null, tint = accentColor, modifier = Modifier.size(18.dp))
        }
        Spacer(Modifier.height(8.dp))
        Text(
            text = value,
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            color = TextPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = label,
            fontSize = 12.sp,
            color = TextSecondary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
fun ClinicalEmptyState(
    icon: ImageVector,
    title: String,
    description: String,
    modifier: Modifier = Modifier
) {
    ClinicalSurfaceCard(modifier = modifier) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(SentinelPrimaryContainer, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = null, tint = SentinelPrimary, modifier = Modifier.size(24.dp))
            }
            Spacer(Modifier.height(12.dp))
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = TextPrimary
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary
            )
        }
    }
}

/**
 * High-contrast input text style for clinical light-surface screens.
 * Explicitly binds an opaque ink color so text never inherits an invisible or
 * system-inverted content color inside [OutlinedTextField].
 */
@Composable
fun clinicalTextFieldStyle(): TextStyle =
    MaterialTheme.typography.bodyLarge.copy(
        color = TextPrimary,
        fontWeight = FontWeight.Normal
    )

/**
 * High-contrast input text style that follows [MaterialTheme.colorScheme] for screens
 * supporting light, dark, and AMOLED themes.
 */
@Composable
fun adaptiveTextFieldStyle(): TextStyle =
    MaterialTheme.typography.bodyLarge.copy(
        color = MaterialTheme.colorScheme.onSurface,
        fontWeight = FontWeight.Normal
    )

/**
 * Crisp clinical [TextFieldColors] for light-surface cards and dialogs where background surfaces
 * are fixed to bright white/clinical gray regardless of dark-mode theme overrides.
 */
@Composable
fun clinicalOutlinedTextFieldColors(
    focusedContainerColor: Color = SurfaceLight,
    unfocusedContainerColor: Color = Color(0xFFF6F8FB),
    unfocusedBorderColor: Color = Color(0xFFCFD6E2)
): TextFieldColors = buildSentinelOutlinedTextFieldColors(
    textColor = TextPrimary,
    disabledTextColor = TextSecondary,
    focusedContainerColor = focusedContainerColor,
    unfocusedContainerColor = unfocusedContainerColor,
    disabledContainerColor = SurfaceSubtle,
    errorContainerColor = Color(0xFFFEF2F2),
    cursorColor = SentinelPrimary,
    focusedBorderColor = SentinelPrimary,
    unfocusedBorderColor = unfocusedBorderColor,
    disabledBorderColor = BorderColor,
    errorColor = MaterialTheme.colorScheme.error,
    focusedLabelColor = SentinelPrimary,
    unfocusedLabelColor = TextSecondary,
    placeholderColor = TextSecondary,
    focusedLeadingIconColor = SentinelPrimary,
    unfocusedLeadingIconColor = TextSecondary,
    trailingIconColor = TextSecondary,
    supportingTextColor = TextSecondary
)

/**
 * Theme-adaptive [TextFieldColors] derived from [MaterialTheme.colorScheme] with crisp
 * unfocused outlines, readable placeholders, explicit container fills, and high-contrast text.
 */
@Composable
fun adaptiveOutlinedTextFieldColors(
    focusedContainerColor: Color = MaterialTheme.colorScheme.surface,
    unfocusedContainerColor: Color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)
): TextFieldColors {
    val scheme = MaterialTheme.colorScheme
    return buildSentinelOutlinedTextFieldColors(
        textColor = scheme.onSurface,
        disabledTextColor = scheme.onSurface.copy(alpha = 0.6f),
        focusedContainerColor = focusedContainerColor,
        unfocusedContainerColor = unfocusedContainerColor,
        disabledContainerColor = scheme.surfaceVariant.copy(alpha = 0.2f),
        errorContainerColor = scheme.errorContainer.copy(alpha = 0.25f),
        cursorColor = scheme.primary,
        focusedBorderColor = scheme.primary,
        unfocusedBorderColor = scheme.onSurfaceVariant.copy(alpha = 0.45f),
        disabledBorderColor = scheme.outline.copy(alpha = 0.4f),
        errorColor = scheme.error,
        focusedLabelColor = scheme.primary,
        unfocusedLabelColor = scheme.onSurfaceVariant,
        placeholderColor = scheme.onSurfaceVariant.copy(alpha = 0.85f),
        focusedLeadingIconColor = scheme.primary,
        unfocusedLeadingIconColor = scheme.onSurfaceVariant,
        trailingIconColor = scheme.onSurfaceVariant,
        supportingTextColor = scheme.onSurfaceVariant
    )
}

@Composable
private fun buildSentinelOutlinedTextFieldColors(
    textColor: Color,
    disabledTextColor: Color,
    focusedContainerColor: Color,
    unfocusedContainerColor: Color,
    disabledContainerColor: Color,
    errorContainerColor: Color,
    cursorColor: Color,
    focusedBorderColor: Color,
    unfocusedBorderColor: Color,
    disabledBorderColor: Color,
    errorColor: Color,
    focusedLabelColor: Color,
    unfocusedLabelColor: Color,
    placeholderColor: Color,
    focusedLeadingIconColor: Color,
    unfocusedLeadingIconColor: Color,
    trailingIconColor: Color,
    supportingTextColor: Color
): TextFieldColors = OutlinedTextFieldDefaults.colors(
    focusedTextColor = textColor,
    unfocusedTextColor = textColor,
    disabledTextColor = disabledTextColor,
    errorTextColor = textColor,
    focusedContainerColor = focusedContainerColor,
    unfocusedContainerColor = unfocusedContainerColor,
    disabledContainerColor = disabledContainerColor,
    errorContainerColor = errorContainerColor,
    cursorColor = cursorColor,
    errorCursorColor = errorColor,
    selectionColors = TextSelectionColors(
        handleColor = cursorColor,
        backgroundColor = cursorColor.copy(alpha = 0.22f)
    ),
    focusedBorderColor = focusedBorderColor,
    unfocusedBorderColor = unfocusedBorderColor,
    disabledBorderColor = disabledBorderColor,
    errorBorderColor = errorColor,
    focusedLeadingIconColor = focusedLeadingIconColor,
    unfocusedLeadingIconColor = unfocusedLeadingIconColor,
    disabledLeadingIconColor = disabledTextColor,
    errorLeadingIconColor = errorColor,
    focusedTrailingIconColor = trailingIconColor,
    unfocusedTrailingIconColor = trailingIconColor,
    disabledTrailingIconColor = disabledTextColor,
    errorTrailingIconColor = errorColor,
    focusedLabelColor = focusedLabelColor,
    unfocusedLabelColor = unfocusedLabelColor,
    disabledLabelColor = disabledTextColor,
    errorLabelColor = errorColor,
    focusedPlaceholderColor = placeholderColor,
    unfocusedPlaceholderColor = placeholderColor,
    disabledPlaceholderColor = disabledTextColor,
    errorPlaceholderColor = placeholderColor,
    focusedSupportingTextColor = supportingTextColor,
    unfocusedSupportingTextColor = supportingTextColor,
    disabledSupportingTextColor = disabledTextColor,
    errorSupportingTextColor = errorColor
)


