package com.deepfakeshield.feature.onboarding

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import androidx.annotation.DrawableRes
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import kotlinx.coroutines.launch

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

// Brand Tokens aligned with Sentinel Forensics DESIGN.md & Master Reference
private val BrandTextPrimary = Color(0xFF17191F)
private val BrandTextSecondary = Color(0xFF747B87)
private val BrandPrimaryBlue = Color(0xFF1E60EE)
private val IndicatorInactive = Color(0xFFD4D8E2)

/**
 * Redesigned Sentinel Forensics Onboarding Experience.
 *
 * Implements non-destructive full-bleed background hero alignment, seamless mathematical
 * bottom blending into pure white, proportional typography spacing, dynamic expanding pill
 * indicators, and standard Android system navigation padding.
 */
@Composable
fun OnboardingScreen(
    onComplete: () -> Unit
) {
    val context = LocalContext.current
    val view = LocalView.current
    val pages = remember { getOnboardingPages() }
    val pagerState = rememberPagerState(pageCount = { pages.size })
    val scope = rememberCoroutineScope()
    var isNavigating by remember { mutableStateOf(false) }

    // Enforce crisp dark status bar icons and navigation bar icons
    val activity = remember(context) { context.findActivity() }
    SideEffect {
        activity?.window?.let { window ->
            val insets = WindowCompat.getInsetsController(window, window.decorView)
            insets.isAppearanceLightStatusBars = true
            insets.isAppearanceLightNavigationBars = true
        }
    }

    // Stop background overlay service during onboarding
    DisposableEffect(Unit) {
        try {
            val bubbleIntent = Intent(context, Class.forName("com.deepfakeshield.service.FloatingBubbleService"))
            context.stopService(bubbleIntent)
        } catch (_: Exception) {}

        onDispose {}
    }

    val handleComplete: () -> Unit = {
        if (!isNavigating) {
            isNavigating = true
            onComplete()
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.White)
    ) {
        // Swipable Pages: Full-bleed Hero Background + Positioned Typography
        HorizontalPager(
            state = pagerState,
            modifier = Modifier.fillMaxSize(),
            userScrollEnabled = true
        ) { pageIndex ->
            OnboardingPageItem(
                page = pages[pageIndex]
            )
        }

        // Top App Bar: "Skip" button (Screens 2, 3, 4)
        AnimatedVisibility(
            visible = pagerState.currentPage > 0,
            enter = fadeIn(tween(250)),
            exit = fadeOut(tween(200)),
            modifier = Modifier
                .align(Alignment.TopEnd)
                .statusBarsPadding()
                .padding(end = 16.dp, top = 6.dp)
        ) {
            TextButton(
                onClick = handleComplete,
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
            ) {
                Text(
                    text = "Skip",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium,
                    color = BrandPrimaryBlue
                )
            }
        }

        // Fixed Bottom Controls: Responsive Indicators + Morphing Action Buttons
        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Animated Dot / Pill Indicators
            OnboardingPageIndicator(
                pageCount = pages.size,
                currentPage = pagerState.currentPage
            )

            Spacer(modifier = Modifier.height(26.dp))

            // Navigation Actions: Morph between single "Get Started" and "Back / Next"
            AnimatedContent(
                targetState = pagerState.currentPage,
                transitionSpec = {
                    fadeIn(animationSpec = tween(220)) togetherWith
                    fadeOut(animationSpec = tween(150))
                },
                modifier = Modifier.fillMaxWidth(),
                label = "onboarding_actions_transition"
            ) { currentPage ->
                if (currentPage == 0) {
                    // Screen 1: Full-width "Get Started →" button
                    Button(
                        onClick = {
                            scope.launch {
                                pagerState.animateScrollToPage(1)
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(54.dp),
                        shape = RoundedCornerShape(16.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = BrandPrimaryBlue
                        ),
                        elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Text(
                                text = "Get Started",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color.White
                            )
                            Spacer(Modifier.width(8.dp))
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                } else {
                    // Screens 2, 3, 4: "Back" text button + Primary action ("Next →" / "Continue →")
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(54.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(
                            onClick = {
                                scope.launch {
                                    pagerState.animateScrollToPage(currentPage - 1)
                                }
                            },
                            modifier = Modifier.height(48.dp)
                        ) {
                            Text(
                                text = "Back",
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Medium,
                                color = BrandTextSecondary
                            )
                        }

                        Button(
                            onClick = {
                                if (currentPage < pages.lastIndex) {
                                    scope.launch {
                                        pagerState.animateScrollToPage(currentPage + 1)
                                    }
                                } else {
                                    handleComplete()
                                }
                            },
                            modifier = Modifier
                                .height(52.dp)
                                .defaultMinSize(minWidth = 140.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = BrandPrimaryBlue
                            ),
                            elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp),
                            contentPadding = PaddingValues(horizontal = 24.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.Center
                            ) {
                                Text(
                                    text = if (currentPage == pages.lastIndex) "Continue" else "Next",
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = Color.White
                                )
                                Spacer(Modifier.width(8.dp))
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                                    contentDescription = null,
                                    tint = Color.White,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * Individual Onboarding Page Item.
 *
 * Implements non-destructive full-bleed background hero alignment where the image
 * is never cropped horizontally or vertically, naturally dissolving into pure white
 * where the typography rests.
 */
@Composable
private fun OnboardingPageItem(
    page: OnboardingPageData
) {
    Box(
        modifier = Modifier.fillMaxSize()
    ) {
        // Full-bleed Hero Background Artwork:
        // Anchored at top, completely uncropped, seamlessly fading into white
        Image(
            painter = painterResource(id = page.imageRes),
            contentDescription = null,
            modifier = Modifier.fillMaxSize(),
            contentScale = ContentScale.Crop,
            alignment = Alignment.TopCenter
        )

        // Typography Container:
        // Anchored cleanly to the bottom above the fixed indicator & button controls (148dp),
        // positioning the title and description on the pristine pure white canvas below the 3D pedestal
        // with generous breathing room and zero possibility of colliding with the 3D illustration.
        Column(
            modifier = Modifier
                .fillMaxSize()
                .navigationBarsPadding()
                .padding(bottom = 148.dp)
                .padding(horizontal = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Bottom
        ) {
            if (page.isBrandTitle) {
                // Screen 1: Two-tone Brand Headline
                Text(
                    text = buildAnnotatedString {
                        withStyle(
                            style = SpanStyle(
                                color = BrandTextPrimary,
                                fontWeight = FontWeight.Bold
                            )
                        ) {
                            append("Sentinel ")
                        }
                        withStyle(
                            style = SpanStyle(
                                color = BrandPrimaryBlue,
                                fontWeight = FontWeight.Bold
                            )
                        ) {
                            append("Forensics")
                        }
                    },
                    fontSize = 28.sp,
                    textAlign = TextAlign.Center,
                    letterSpacing = (-0.5).sp
                )

                Spacer(Modifier.height(10.dp))

                Text(
                    text = page.subtitle,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium,
                    color = BrandTextSecondary,
                    textAlign = TextAlign.Center,
                    letterSpacing = 0.25.sp
                )
            } else {
                // Screens 2, 3, 4: Standard Feature Headlines & Descriptions
                Text(
                    text = page.title,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = BrandTextPrimary,
                    textAlign = TextAlign.Center,
                    lineHeight = 32.sp
                )

                Spacer(Modifier.height(12.dp))

                Text(
                    text = page.subtitle,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Normal,
                    color = BrandTextSecondary,
                    textAlign = TextAlign.Center,
                    lineHeight = 22.sp
                )
            }
        }
    }
}

/**
 * Dynamic expanding pill indicator.
 * Smoothly animates the active indicator into an elongated pill while contracting inactive dots.
 */
@Composable
private fun OnboardingPageIndicator(
    pageCount: Int,
    currentPage: Int
) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        repeat(pageCount) { index ->
            val isSelected = currentPage == index
            val width by animateDpAsState(
                targetValue = if (isSelected) 26.dp else 6.dp,
                animationSpec = tween(durationMillis = 300, easing = FastOutSlowInEasing),
                label = "indicator_width"
            )
            val color by animateColorAsState(
                targetValue = if (isSelected) BrandPrimaryBlue else IndicatorInactive,
                animationSpec = tween(durationMillis = 300),
                label = "indicator_color"
            )

            Box(
                modifier = Modifier
                    .height(6.dp)
                    .width(width)
                    .clip(CircleShape)
                    .background(color)
            )
        }
    }
}

/**
 * Data specification for onboarding pages.
 */
private data class OnboardingPageData(
    @DrawableRes val imageRes: Int,
    val title: String,
    val subtitle: String,
    val isBrandTitle: Boolean = false
)

private fun getOnboardingPages() = listOf(
    OnboardingPageData(
        imageRes = R.drawable.onboarding_screen_01_bg,
        title = "Sentinel Forensics",
        subtitle = "Detect • Investigate • Stay Safe",
        isBrandTitle = true
    ),
    OnboardingPageData(
        imageRes = R.drawable.onboarding_screen_02_bg,
        title = "Real-Time Protection Everywhere",
        subtitle = "We automatically scan links and messages from SMS, email, and social apps to keep you safe from scams and phishing."
    ),
    OnboardingPageData(
        imageRes = R.drawable.onboarding_screen_03_bg,
        title = "Detect Manipulated Media",
        subtitle = "Analyze photos and videos for deepfakes, hidden data, and tampering using on-device AI models."
    ),
    OnboardingPageData(
        imageRes = R.drawable.onboarding_screen_04_bg,
        title = "Stronger Security for Your Device",
        subtitle = "Scan files, apps, Wi-Fi networks, and phone activity with local analysis and intelligent detection."
    )
)
