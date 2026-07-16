package com.otilm.core.mapper.oid;

import com.otilm.api.model.core.oid.CustomOidEntryDetailResponseDto;
import com.otilm.api.model.core.oid.CustomOidEntryResponseDto;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.api.model.core.oid.properties.AdditionalOidPropertiesDto;
import com.otilm.api.model.core.oid.properties.CertificateExtensionOidPropertiesDto;
import com.otilm.api.model.core.oid.properties.RdnAttributeTypeOidPropertiesDto;
import com.otilm.core.dao.entity.oid.CertificateExtensionCustomOidEntry;
import com.otilm.core.dao.entity.oid.CustomOidEntry;
import com.otilm.core.dao.entity.oid.RdnAttributeTypeCustomOidEntry;

public class CustomOidEntryMapper {

    private CustomOidEntryMapper() {
    }

    public static CustomOidEntryResponseDto toDto(CustomOidEntry entry) {
        CustomOidEntryResponseDto dto = new CustomOidEntryResponseDto();
        populateBaseFields(entry, dto);
        return dto;
    }

    public static CustomOidEntryDetailResponseDto toDetailDto(CustomOidEntry entry) {
        CustomOidEntryDetailResponseDto dto = new CustomOidEntryDetailResponseDto();
        populateBaseFields(entry, dto);
        dto.setAdditionalProperties(toAdditionalProperties(entry));
        return dto;
    }

    public static CustomOidEntryDetailResponseDto toDetailDto(SystemOid systemOid) {
        CustomOidEntryDetailResponseDto dto = new CustomOidEntryDetailResponseDto();
        dto.setOid(systemOid.getOid());
        dto.setCategory(systemOid.getCategory());
        dto.setDisplayName(systemOid.getDisplayName());
        // SystemOid only carries RDN code/altCodes; EKU and GENERIC entries have no additional
        // properties, and the enum has no fields to represent a CERTIFICATE_EXTENSION's typed properties.
        if (systemOid.getCategory() == OidCategory.RDN_ATTRIBUTE_TYPE) {
            RdnAttributeTypeOidPropertiesDto props = new RdnAttributeTypeOidPropertiesDto();
            props.setCode(systemOid.getCode());
            props.setAltCodes(systemOid.getAltCodes());
            dto.setAdditionalProperties(props);
        }
        return dto;
    }

    private static AdditionalOidPropertiesDto toAdditionalProperties(CustomOidEntry entry) {
        if (entry instanceof RdnAttributeTypeCustomOidEntry rdn) {
            RdnAttributeTypeOidPropertiesDto dto = new RdnAttributeTypeOidPropertiesDto();
            dto.setCode(rdn.getCode());
            dto.setAltCodes(rdn.getAltCodes());
            return dto;
        }
        if (entry instanceof CertificateExtensionCustomOidEntry ext) {
            CertificateExtensionOidPropertiesDto dto = new CertificateExtensionOidPropertiesDto();
            dto.setDefaultCritical(ext.getDefaultCritical());
            dto.setValueEncoding(ext.getValueEncoding());
            return dto;
        }
        return null;
    }

    private static void populateBaseFields(CustomOidEntry entry, CustomOidEntryResponseDto dto) {
        dto.setOid(entry.getOid());
        dto.setCategory(entry.getCategory());
        dto.setDescription(entry.getDescription());
        dto.setDisplayName(entry.getDisplayName());
    }
}
