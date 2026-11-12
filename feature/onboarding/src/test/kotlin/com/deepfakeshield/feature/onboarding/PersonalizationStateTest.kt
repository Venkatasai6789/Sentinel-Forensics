package com.deepfakeshield.feature.onboarding

import org.junit.Assert.*
import org.junit.Test

class PersonalizationStateTest {

    @Test
    fun `default UI state has 0 selected, country is IN, and cannot continue`() {
        val state = SecurityPreferencesUiState()
        assertEquals(0, state.selectedCount)
        assertEquals("IN", state.countryCode)
        assertFalse(state.isSaving)
        assertNull(state.errorMessage)
        assertFalse(state.canContinue)
    }

    @Test
    fun `selecting fewer than 3 categories cannot continue`() {
        val state1 = SecurityPreferencesUiState(
            selectedCategories = setOf(SecurityCategory.SCAM_MESSAGE)
        )
        assertEquals(1, state1.selectedCount)
        assertFalse(state1.canContinue)

        val state2 = state1.copy(
            selectedCategories = setOf(
                SecurityCategory.SCAM_MESSAGE,
                SecurityCategory.DEEPFAKE
            )
        )
        assertEquals(2, state2.selectedCount)
        assertFalse(state2.canContinue)
    }

    @Test
    fun `selecting 3 or more categories enables continue`() {
        val state3 = SecurityPreferencesUiState(
            selectedCategories = setOf(
                SecurityCategory.SCAM_MESSAGE,
                SecurityCategory.DEEPFAKE,
                SecurityCategory.PHOTO_FORENSICS
            )
        )
        assertEquals(3, state3.selectedCount)
        assertTrue(state3.canContinue)

        val state4 = state3.copy(
            selectedCategories = state3.selectedCategories + SecurityCategory.PHISHING_LINKS
        )
        assertEquals(4, state4.selectedCount)
        assertTrue(state4.canContinue)
    }

    @Test
    fun `isSaving flag disables continue even with 3 categories selected`() {
        val state = SecurityPreferencesUiState(
            selectedCategories = setOf(
                SecurityCategory.SCAM_MESSAGE,
                SecurityCategory.DEEPFAKE,
                SecurityCategory.PHOTO_FORENSICS
            ),
            isSaving = true
        )
        assertTrue(state.selectedCount >= 3)
        assertFalse(state.canContinue)
    }

    @Test
    fun `verify exactly eight categories in required order with correct IDs`() {
        val categories = SecurityCategory.values()
        assertEquals(8, categories.size)

        assertEquals(SecurityCategory.SCAM_MESSAGE, categories[0])
        assertEquals("SCAM_MESSAGE", categories[0].id)
        assertEquals("Scam & Message Protection", categories[0].title)

        assertEquals(SecurityCategory.DEEPFAKE, categories[1])
        assertEquals("DEEPFAKE", categories[1].id)
        assertEquals("Deepfake Detection", categories[1].title)

        assertEquals(SecurityCategory.PHOTO_FORENSICS, categories[2])
        assertEquals("PHOTO_FORENSICS", categories[2].id)
        assertEquals("Photo Forensics", categories[2].title)

        assertEquals(SecurityCategory.PHISHING_LINKS, categories[3])
        assertEquals("PHISHING_LINKS", categories[3].id)
        assertEquals("Phishing Link Finder", categories[3].title)

        assertEquals(SecurityCategory.WIFI_SECURITY, categories[4])
        assertEquals("WIFI_SECURITY", categories[4].id)
        assertEquals("Wi-Fi & Network Security", categories[4].title)

        assertEquals(SecurityCategory.DEVICE_SCANNER, categories[5])
        assertEquals("DEVICE_SCANNER", categories[5].id)
        assertEquals("Device Threat Scanner", categories[5].title)

        assertEquals(SecurityCategory.CALL_SHIELD, categories[6])
        assertEquals("CALL_SHIELD", categories[6].id)
        assertEquals("Scam Numbers & Call Shield", categories[6].title)

        assertEquals(SecurityCategory.PASSWORD_SECURITY, categories[7])
        assertEquals("PASSWORD_SECURITY", categories[7].id)
        assertEquals("Password Security", categories[7].title)
    }

    @Test
    fun `toggle category adds and removes properly`() {
        var selected = setOf<SecurityCategory>()

        // Add
        selected = selected + SecurityCategory.DEEPFAKE
        assertTrue(SecurityCategory.DEEPFAKE in selected)
        assertEquals(1, selected.size)

        // Add second
        selected = selected + SecurityCategory.PASSWORD_SECURITY
        assertEquals(2, selected.size)

        // Remove first
        selected = selected - SecurityCategory.DEEPFAKE
        assertFalse(SecurityCategory.DEEPFAKE in selected)
        assertTrue(SecurityCategory.PASSWORD_SECURITY in selected)
        assertEquals(1, selected.size)
    }
}
