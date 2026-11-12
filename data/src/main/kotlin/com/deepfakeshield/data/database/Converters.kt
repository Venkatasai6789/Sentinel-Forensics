package com.deepfakeshield.data.database

import androidx.room.TypeConverter
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.RiskSeverity
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.core.model.ThreatSource
import com.deepfakeshield.core.model.ThreatType

class Converters {
    @TypeConverter
    fun fromRiskSeverity(value: RiskSeverity): String = value.name
    
    @TypeConverter
    fun toRiskSeverity(value: String): RiskSeverity =
        try { RiskSeverity.valueOf(value) } catch (e: Exception) { android.util.Log.w("Converters", "Invalid value: $value", e); RiskSeverity.LOW }
    
    @TypeConverter
    fun fromThreatType(value: ThreatType): String = value.name
    
    @TypeConverter
    fun toThreatType(value: String): ThreatType =
        try { ThreatType.valueOf(value) } catch (e: Exception) { android.util.Log.w("Converters", "Invalid value: $value", e); ThreatType.UNKNOWN }
    
    @TypeConverter
    fun fromThreatSource(value: ThreatSource): String = value.name
    
    @TypeConverter
    fun toThreatSource(value: String): ThreatSource =
        try { ThreatSource.valueOf(value) } catch (e: Exception) { android.util.Log.w("Converters", "Invalid value: $value", e); ThreatSource.MANUAL_SCAN }

    @TypeConverter
    fun fromSecurityModule(value: SecurityModule): String = value.name

    @TypeConverter
    fun toSecurityModule(value: String): SecurityModule =
        try { SecurityModule.valueOf(value) } catch (e: Exception) { SecurityModule.MESSAGE_SHIELD }

    @TypeConverter
    fun fromAnalysisStatus(value: AnalysisStatus): String = value.name

    @TypeConverter
    fun toAnalysisStatus(value: String): AnalysisStatus =
        try { AnalysisStatus.valueOf(value) } catch (e: Exception) { AnalysisStatus.FAILED }

    @TypeConverter
    fun fromSecurityVerdict(value: SecurityVerdict): String = value.name

    @TypeConverter
    fun toSecurityVerdict(value: String): SecurityVerdict =
        try { SecurityVerdict.valueOf(value) } catch (e: Exception) { SecurityVerdict.INCONCLUSIVE }
}
