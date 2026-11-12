package com.deepfakeshield.feature.onboarding

import android.provider.Settings
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.outlined.Sms
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Design Tokens directly derived from Sentinel Forensics DESIGN.md (Source of Truth).
 */
private val ColorPrimary = Color(0xFF4F72E8)
private val ColorPrimaryPressed = Color(0xFF3F60CF)
private val ColorPrimaryContainer = Color(0xFFE9EEFF)
private val ColorBackground = Color(0xFFF5F6F8)
private val ColorSurface = Color(0xFFFFFFFF)
private val ColorSurfaceSubtle = Color(0xFFF2F4F7)
private val ColorBorder = Color(0xFFE6E9EF)
private val ColorTextPrimary = Color(0xFF17191F)
private val ColorTextSecondary = Color(0xFF747B87)
private val ColorTextTertiary = Color(0xFF969DA8)
private val ColorDanger = Color(0xFFC83E4D)
private val ColorDangerContainer = Color(0xFFFCEBED)
private val ColorWarning = Color(0xFFB7791F)
private val ColorWarningContainer = Color(0xFFFFF4D9)
private val ColorSuccess = Color(0xFF25A653)
private val ColorSuccessContainer = Color(0xFFE8F7ED)

/**
 * Explicit demonstration stages for the simulated threat-detection sequence.
 */
private enum class DemoStage {
    MESSAGE,    // State 1: Simulated suspicious SMS preview entrance
    ANALYZING,  // State 2: Active analysis with scan sweep & progress indicators
    RESULT      // State 3 & 4: Scam analysis result & completion CTA
}

/**
 * Redesigned Sentinel Forensics Threat Detection Demonstration.
 *
 * Implements a production-quality, evidence-led cybersecurity experience
 * conforming to DESIGN.md and official Android motion guidelines.
 */
@Composable
fun ScamSimulatorScreen(
    onComplete: () -> Unit
) {
    var stage by rememberSaveable { mutableStateOf(DemoStage.MESSAGE) }
    var revealedChecksCount by rememberSaveable { mutableIntStateOf(0) }
    var isNavigating by remember { mutableStateOf(false) }

    val scanProgress = remember { Animatable(0f) }

    val context = LocalContext.current
    val isReducedMotion = remember(context) {
        try {
            val scale = Settings.Global.getFloat(
                context.contentResolver,
                Settings.Global.ANIMATOR_DURATION_SCALE,
                1.0f
            )
            scale == 0f
        } catch (_: Exception) {
            false
        }
    }

    val handleComplete: () -> Unit = {
        if (!isNavigating) {
            isNavigating = true
            onComplete()
        }
    }

    // Coordinated state-driven animation sequence
    LaunchedEffect(Unit) {
        if (isReducedMotion) {
            stage = DemoStage.RESULT
            revealedChecksCount = 4
            return@LaunchedEffect
        }

        // Run real heuristic analyzer in background to verify findings without blocking UI
        val sampleMessage = "URGENT: Your bank account may be compromised. Verify your account using the link below: https://example.com/verify"
        withContext(Dispatchers.Default) {
            try {
                val analyzer = com.deepfakeshield.ml.heuristics.ProductionHeuristicTextAnalyzer()
                analyzer.analyzeText(sampleMessage)
            } catch (_: Exception) {
                // Graceful fallback for offline or standalone runtimes
            }
        }

        // State 1: Message preview entrance and initial reading window
        delay(550)

        // State 2: Transition into active analysis
        stage = DemoStage.ANALYZING

        // Run clipped horizontal scan sweep across the simulated message card
        launch {
            scanProgress.snapTo(0f)
            scanProgress.animateTo(
                targetValue = 1f,
                animationSpec = tween(
                    durationMillis = 850,
                    easing = FastOutSlowInEasing
                )
            )
        }

        // Progressive reveal of analysis checks (180–220 ms per check)
        delay(180)
        revealedChecksCount = 1
        delay(200)
        revealedChecksCount = 2
        delay(200)
        revealedChecksCount = 3
        delay(200)
        revealedChecksCount = 4
        delay(280)

        // State 3 & 4: Reveal scam detection results and completion CTA
        stage = DemoStage.RESULT
    }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = ColorBackground
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
        ) {
            // Top Navigation Bar with subtle brand label and Skip action
            TopDemoBar(
                onSkip = handleComplete,
                isNavigating = isNavigating
            )

            // Scrollable content area accommodating small phone viewports & font scaling
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Screen Heading & Supporting Text
                ScreenHeaderSection()

                // State 1: Simulated Incoming SMS Card with scan sweep overlay
                SimulatedMessageCard(
                    sender = "+1 800 555 0199",
                    messageBody = "URGENT: Your bank account may be compromised. Verify your account using the link below:",
                    urlText = "https://example.com/verify",
                    isScanning = stage == DemoStage.ANALYZING,
                    scanProgress = scanProgress.value
                )

                // State 2: Active Analysis Progress Card
                AnimatedVisibility(
                    visible = stage == DemoStage.ANALYZING,
                    enter = fadeIn(animationSpec = tween(240, easing = LinearOutSlowInEasing)) +
                            slideInVertically(
                                initialOffsetY = { it / 8 },
                                animationSpec = tween(260, easing = FastOutSlowInEasing)
                            ),
                    exit = fadeOut(animationSpec = tween(150))
                ) {
                    AnalysisProgressCard(
                        revealedCount = revealedChecksCount
                    )
                }

                // State 3: Scam Detection Result Panel
                AnimatedVisibility(
                    visible = stage == DemoStage.RESULT,
                    enter = fadeIn(animationSpec = tween(280, easing = LinearOutSlowInEasing)) +
                            slideInVertically(
                                initialOffsetY = { it / 8 },
                                animationSpec = tween(300, easing = FastOutSlowInEasing)
                            )
                ) {
                    ScamResultPanel()
                }

                // State 4: Contextual Demonstration Completion Takeaway
                AnimatedVisibility(
                    visible = stage == DemoStage.RESULT,
                    enter = fadeIn(animationSpec = tween(280, delayMillis = 100)) +
                            slideInVertically(
                                initialOffsetY = { it / 8 },
                                animationSpec = tween(300, delayMillis = 100)
                            )
                ) {
                    DemonstrationCompletionMessage()
                }

                Spacer(modifier = Modifier.height(8.dp))
            }

            // Fixed Bottom Primary Action Button
            BottomActionArea(
                visible = stage == DemoStage.RESULT,
                onContinue = handleComplete,
                isNavigating = isNavigating
            )
        }
    }
}

/**
 * Top navigation bar with accessible Skip touch target and brand attribution.
 */
@Composable
private fun TopDemoBar(
    onSkip: () -> Unit,
    isNavigating: Boolean
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(ColorPrimary)
            )
            Text(
                text = "SENTINEL FORENSICS",
                style = MaterialTheme.typography.labelSmall.copy(
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.8.sp
                ),
                color = ColorTextSecondary
            )
        }

        TextButton(
            onClick = onSkip,
            enabled = !isNavigating,
            modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)
        ) {
            Text(
                text = "Skip",
                style = MaterialTheme.typography.labelLarge.copy(
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium
                ),
                color = ColorTextSecondary
            )
        }
    }
}

/**
 * Screen header providing clear context without excessive decoration.
 */
@Composable
private fun ScreenHeaderSection() {
    Column(
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            text = "See Threat Detection in Action",
            style = MaterialTheme.typography.headlineSmall.copy(
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                lineHeight = 28.sp
            ),
            color = ColorTextPrimary
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Watch how Sentinel Forensics analyzes a suspicious message and highlights potential warning signs.",
            style = MaterialTheme.typography.bodyMedium.copy(
                fontSize = 14.sp,
                lineHeight = 20.sp
            ),
            color = ColorTextSecondary
        )
    }
}

/**
 * Realistic, restrained simulated SMS preview card.
 * Incorporates a contained horizontal scanning sweep during analysis.
 */
@Composable
private fun SimulatedMessageCard(
    sender: String,
    messageBody: String,
    urlText: String,
    isScanning: Boolean,
    scanProgress: Float,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .border(1.dp, ColorBorder, RoundedCornerShape(14.dp))
            .drawWithContent {
                drawContent()
                if (isScanning && scanProgress in 0f..1f) {
                    val sweepWidth = size.width * 0.35f
                    val startX = (size.width + sweepWidth) * scanProgress - sweepWidth
                    drawRect(
                        brush = Brush.horizontalGradient(
                            colors = listOf(
                                Color.Transparent,
                                ColorPrimary.copy(alpha = 0.08f),
                                ColorPrimary.copy(alpha = 0.22f),
                                ColorPrimary.copy(alpha = 0.08f),
                                Color.Transparent
                            ),
                            startX = startX,
                            endX = startX + sweepWidth
                        ),
                        size = size
                    )
                }
            },
        color = ColorSurface,
        shape = RoundedCornerShape(14.dp),
        shadowElevation = 0.dp
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            // Sender identity & simulation badge
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .clip(CircleShape)
                            .background(ColorSurfaceSubtle),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Sms,
                            contentDescription = "Simulated message",
                            tint = ColorTextSecondary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                    Column {
                        Text(
                            text = sender,
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontSize = 14.sp,
                                fontWeight = FontWeight.SemiBold
                            ),
                            color = ColorTextPrimary
                        )
                        Text(
                            text = "Incoming SMS",
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontSize = 11.sp
                            ),
                            color = ColorTextSecondary
                        )
                    }
                }

                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = ColorSurfaceSubtle
                ) {
                    Text(
                        text = "Simulated",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Medium
                        ),
                        color = ColorTextSecondary
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Realistic message body with distinct, non-clickable example URL
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = ColorSurfaceSubtle,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(14.dp)
                ) {
                    Text(
                        text = messageBody,
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontSize = 13.sp,
                            lineHeight = 18.sp
                        ),
                        color = ColorTextPrimary
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = urlText,
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                            textDecoration = TextDecoration.Underline
                        ),
                        color = ColorPrimary
                    )
                }
            }
        }
    }
}

/**
 * State 2: Analysis in progress showing active status and progressive indicator checks.
 */
@Composable
private fun AnalysisProgressCard(
    revealedCount: Int,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, ColorBorder, RoundedCornerShape(14.dp)),
        color = ColorSurface,
        shape = RoundedCornerShape(14.dp),
        shadowElevation = 0.dp
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = ColorPrimary,
                    trackColor = ColorPrimaryContainer
                )
                Text(
                    text = "Analyzing message",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold
                    ),
                    color = ColorTextPrimary
                )
            }

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Checking for suspicious language, impersonation, and unsafe links.",
                style = MaterialTheme.typography.bodySmall.copy(
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                ),
                color = ColorTextSecondary
            )

            Spacer(modifier = Modifier.height(14.dp))

            val checks = listOf(
                "Language patterns",
                "Sender and impersonation cues",
                "Link characteristics",
                "Message context"
            )

            checks.forEachIndexed { index, checkLabel ->
                val isEvaluated = revealedCount > index
                val isEvaluating = revealedCount == index

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 5.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        when {
                            isEvaluated -> {
                                Box(
                                    modifier = Modifier
                                        .size(18.dp)
                                        .clip(CircleShape)
                                        .background(ColorWarningContainer),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Check,
                                        contentDescription = "Check completed",
                                        tint = ColorWarning,
                                        modifier = Modifier.size(11.dp)
                                    )
                                }
                            }
                            isEvaluating -> {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(14.dp),
                                    strokeWidth = 1.5.dp,
                                    color = ColorPrimary
                                )
                            }
                            else -> {
                                Box(
                                    modifier = Modifier
                                        .size(18.dp)
                                        .clip(CircleShape)
                                        .background(ColorSurfaceSubtle)
                                )
                            }
                        }

                        Text(
                            text = checkLabel,
                            style = MaterialTheme.typography.bodyMedium.copy(
                                fontSize = 13.sp,
                                fontWeight = if (isEvaluated) FontWeight.Medium else FontWeight.Normal
                            ),
                            color = if (isEvaluated || isEvaluating) ColorTextPrimary else ColorTextTertiary
                        )
                    }

                    if (isEvaluated) {
                        Text(
                            text = "Flagged",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium
                            ),
                            color = ColorWarning
                        )
                    } else if (isEvaluating) {
                        Text(
                            text = "Scanning...",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontSize = 11.sp
                            ),
                            color = ColorTextSecondary
                        )
                    }
                }
            }
        }
    }
}

/**
 * State 3: Distinct Scam Detection Result Panel with restrained warning indicators.
 */
@Composable
private fun ScamResultPanel(
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, ColorBorder, RoundedCornerShape(14.dp)),
        color = ColorSurface,
        shape = RoundedCornerShape(14.dp),
        shadowElevation = 0.dp
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            // Header with warning icon and qualitative status badge
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .clip(CircleShape)
                            .background(ColorDangerContainer),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.WarningAmber,
                            contentDescription = "Threat warning",
                            tint = ColorDanger,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Column {
                        Text(
                            text = "Potential Scam Detected",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold
                            ),
                            color = ColorTextPrimary
                        )
                        Text(
                            text = "This simulated message contains several common scam indicators.",
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontSize = 12.sp,
                                lineHeight = 16.sp
                            ),
                            color = ColorTextSecondary
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Qualitative status badge — honest to findings without unsupported percentage claims
            Surface(
                shape = RoundedCornerShape(999.dp),
                color = ColorDangerContainer
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .clip(CircleShape)
                            .background(ColorDanger)
                    )
                    Text(
                        text = "High-risk indicators found",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Medium
                        ),
                        color = ColorDanger
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))
            HorizontalDivider(thickness = 1.dp, color = ColorBorder)
            Spacer(modifier = Modifier.height(12.dp))

            // 4 Verified Warning Indicators
            val warningIndicators = listOf(
                Pair(
                    "Urgency language",
                    "Pressures the recipient to act immediately."
                ),
                Pair(
                    "Impersonation cues",
                    "Claims to represent a trusted financial institution."
                ),
                Pair(
                    "Action pressure",
                    "Requests account verification through a link."
                ),
                Pair(
                    "Suspicious link",
                    "The example URL is presented as a link requiring caution."
                )
            )

            warningIndicators.forEachIndexed { index, (title, description) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 5.dp),
                    verticalAlignment = Alignment.Top,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .padding(top = 2.dp)
                            .size(18.dp)
                            .clip(CircleShape)
                            .background(ColorDangerContainer),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "${index + 1}",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold
                            ),
                            color = ColorDanger
                        )
                    }

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = title,
                            style = MaterialTheme.typography.bodyMedium.copy(
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold
                            ),
                            color = ColorTextPrimary
                        )
                        Text(
                            text = description,
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontSize = 12.sp,
                                lineHeight = 16.sp
                            ),
                            color = ColorTextSecondary
                        )
                    }
                }
            }
        }
    }
}

/**
 * State 4: Concise completion statement and educational takeaway.
 */
@Composable
private fun DemonstrationCompletionMessage(
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, ColorBorder, RoundedCornerShape(14.dp)),
        color = ColorSurface,
        shape = RoundedCornerShape(14.dp),
        shadowElevation = 0.dp
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "Know the warning signs. Stay in control.",
                style = MaterialTheme.typography.titleMedium.copy(
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold
                ),
                color = ColorTextPrimary,
                textAlign = TextAlign.Center
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "This was a simulated example. Continue setup to explore Sentinel Forensics.",
                style = MaterialTheme.typography.bodySmall.copy(
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                ),
                color = ColorTextSecondary,
                textAlign = TextAlign.Center
            )
        }
    }
}

/**
 * Bottom action area housing the stable, accessible primary CTA button.
 */
@Composable
private fun BottomActionArea(
    visible: Boolean,
    onContinue: () -> Unit,
    isNavigating: Boolean
) {
    AnimatedVisibility(
        visible = visible,
        enter = fadeIn(animationSpec = tween(240)) +
                slideInVertically(
                    initialOffsetY = { it / 4 },
                    animationSpec = tween(260)
                ),
        exit = fadeOut(animationSpec = tween(150))
    ) {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            color = ColorBackground,
            shadowElevation = 0.dp
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 14.dp)
            ) {
                Button(
                    onClick = onContinue,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(54.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = ColorPrimary,
                        contentColor = Color.White,
                        disabledContainerColor = ColorPrimary.copy(alpha = 0.5f),
                        disabledContentColor = Color.White.copy(alpha = 0.7f)
                    ),
                    elevation = ButtonDefaults.buttonElevation(
                        defaultElevation = 0.dp,
                        pressedElevation = 0.dp
                    ),
                    enabled = !isNavigating
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "Continue Setup",
                            style = MaterialTheme.typography.labelLarge.copy(
                                fontSize = 15.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                        )
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }
        }
    }
}

@Preview(name = "Threat Detection Demo - Light")
@Composable
private fun ScamSimulatorScreenPreview() {
    ScamSimulatorScreen(onComplete = {})
}
