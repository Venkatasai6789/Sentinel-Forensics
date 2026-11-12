package com.deepfakeshield.feature.onboarding

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ImageSearch
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.MarkChatUnread
import androidx.compose.material.icons.outlined.PhoneInTalk
import androidx.compose.material.icons.outlined.PhonelinkLock
import androidx.compose.material.icons.outlined.Videocam
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepfakeshield.data.preferences.UserPreferences
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * 8 Core Security & Forensics Categories defined for Sentinel Forensics.
 * Aligned with DESIGN.md and product specification.
 */
enum class SecurityCategory(
    val id: String,
    val title: String,
    val description: String,
    val icon: ImageVector
) {
    SCAM_MESSAGE(
        id = "SCAM_MESSAGE",
        title = "Scam & Message Protection",
        description = "Identify suspicious messages, scam patterns, and risky content.",
        icon = Icons.Outlined.MarkChatUnread
    ),
    DEEPFAKE(
        id = "DEEPFAKE",
        title = "Deepfake Detection",
        description = "Analyse videos for signs of manipulation or synthetic media.",
        icon = Icons.Outlined.Videocam
    ),
    PHOTO_FORENSICS(
        id = "PHOTO_FORENSICS",
        title = "Photo Forensics",
        description = "Inspect image metadata and indicators of possible manipulation.",
        icon = Icons.Outlined.ImageSearch
    ),
    PHISHING_LINKS(
        id = "PHISHING_LINKS",
        title = "Phishing Link Finder",
        description = "Check URLs and domains for suspicious patterns before proceeding.",
        icon = Icons.Outlined.Link
    ),
    WIFI_SECURITY(
        id = "WIFI_SECURITY",
        title = "Wi-Fi & Network Security",
        description = "Inspect network settings, encryption, and connection risks.",
        icon = Icons.Outlined.Wifi
    ),
    DEVICE_SCANNER(
        id = "DEVICE_SCANNER",
        title = "Device Threat Scanner",
        description = "Scan supported local files and installed applications for threats.",
        icon = Icons.Outlined.PhonelinkLock
    ),
    CALL_SHIELD(
        id = "CALL_SHIELD",
        title = "Scam Numbers & Call Shield",
        description = "Review scam indicators in supported caller and call-history data.",
        icon = Icons.Outlined.PhoneInTalk
    ),
    PASSWORD_SECURITY(
        id = "PASSWORD_SECURITY",
        title = "Password Security",
        description = "Generate strong passwords and manage them in a protected local vault.",
        icon = Icons.Outlined.Key
    )
}

/**
 * UI State for Sentinel Forensics Personalisation Screen.
 * Default region is locked to India ("IN") as per product requirement.
 */
data class SecurityPreferencesUiState(
    val selectedCategories: Set<SecurityCategory> = emptySet(),
    val countryCode: String = "IN",
    val isSaving: Boolean = false,
    val errorMessage: String? = null
) {
    val selectedCount: Int
        get() = selectedCategories.size

    val canContinue: Boolean
        get() = selectedCategories.size >= 3 && !isSaving
}

@HiltViewModel
class PersonalizationViewModel @Inject constructor(
    private val userPreferences: UserPreferences
) : ViewModel() {

    private val _uiState = MutableStateFlow(SecurityPreferencesUiState())
    val uiState: StateFlow<SecurityPreferencesUiState> = _uiState.asStateFlow()

    init {
        restorePreferences()
    }

    private fun restorePreferences() {
        viewModelScope.launch {
            try {
                val savedCategoryIds = userPreferences.personalizationCategories.first()
                if (savedCategoryIds.isNotEmpty()) {
                    val restored = SecurityCategory.values().filter {
                        it.name in savedCategoryIds || it.id in savedCategoryIds
                    }.toSet()
                    if (restored.isNotEmpty()) {
                        _uiState.update { it.copy(selectedCategories = restored) }
                    }
                }
            } catch (_: Exception) {
                // Ignore and use default initial state
            }
        }
    }

    fun toggleCategory(category: SecurityCategory) {
        val current = _uiState.value.selectedCategories
        val updated = if (category in current) {
            current - category
        } else {
            current + category
        }

        _uiState.update {
            it.copy(
                selectedCategories = updated,
                errorMessage = null
            )
        }
    }

    fun continueToNextScreen(onSuccess: (Set<String>, String) -> Unit) {
        val current = _uiState.value
        if (current.isSaving) return

        if (current.selectedCategories.size < 3) {
            _uiState.update {
                it.copy(errorMessage = "Select at least 3 areas to continue.")
            }
            return
        }

        _uiState.update { it.copy(isSaving = true, errorMessage = null) }

        viewModelScope.launch {
            try {
                val categoryIds = current.selectedCategories.map { it.name }.toSet()
                userPreferences.setPersonalizationPreferences(
                    categories = categoryIds,
                    country = "IN",
                    completed = true
                )
                onSuccess(categoryIds, "IN")
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isSaving = false,
                        errorMessage = "Unable to save preferences. Please try again."
                    )
                }
            }
        }
    }

    fun skipForNow(onSuccess: (Set<String>, String) -> Unit) {
        val current = _uiState.value
        if (current.isSaving) return

        _uiState.update { it.copy(isSaving = true, errorMessage = null) }

        viewModelScope.launch {
            try {
                userPreferences.setPersonalizationPreferences(
                    categories = emptySet(),
                    country = "IN",
                    completed = true
                )
                onSuccess(emptySet(), "IN")
            } catch (e: Exception) {
                // Safe skip path even on preference save error
                onSuccess(emptySet(), "IN")
            }
        }
    }
}
