package com.otilm.core.mapper.oid;

import com.otilm.api.model.core.oid.CustomOidEntryDetailResponseDto;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.api.model.core.oid.properties.CertificateExtensionOidPropertiesDto;
import com.otilm.api.model.core.oid.properties.RdnAttributeTypeOidPropertiesDto;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plain unit coverage for the system-OID projection — no Spring context. {@code GET /v1/oids/system} returns system
 * entries shaped exactly like custom ones, so a category that carries typed properties must surface them or the
 * response violates its own required-field contract.
 */
class CustomOidEntryMapperTest {

    @Test
    void systemCertificateExtensionCarriesItsTypedProperties() {
        // given — CertificateExtensionOidPropertiesDto marks both fields required
        SystemOid keyUsage = SystemOid.KEY_USAGE;

        // when
        CustomOidEntryDetailResponseDto dto = CustomOidEntryMapper.toDetailDto(keyUsage);

        // then
        assertThat(dto.getOid()).isEqualTo("2.5.29.15");
        assertThat(dto.getCategory()).isEqualTo(OidCategory.CERTIFICATE_EXTENSION);
        assertThat(dto.getAdditionalProperties())
                .isInstanceOf(CertificateExtensionOidPropertiesDto.class)
                .satisfies(props -> {
                    CertificateExtensionOidPropertiesDto ext = (CertificateExtensionOidPropertiesDto) props;
                    assertThat(ext.getDefaultCritical()).isTrue();
                    assertThat(ext.getValueEncoding()).isEqualTo(ExtensionValueEncoding.DER);
                });
    }

    @Test
    void systemExtensionSurfacesTheCoreShippedValueSchema() {
        // Core holds values to this module, but a registry row cannot carry it — an entry for a system OID
        // cannot be created — so without surfacing it the operator cannot learn what their value must be.
        CustomOidEntryDetailResponseDto dto = CustomOidEntryMapper.toDetailDto(SystemOid.BASIC_CONSTRAINTS);

        CertificateExtensionOidPropertiesDto ext = (CertificateExtensionOidPropertiesDto) dto.getAdditionalProperties();
        assertThat(ext.getValueSchema()).isNotNull().contains("BasicConstraints ::= SEQUENCE");
    }

    @Test
    void everySystemCertificateExtensionSurfacesBothRequiredFields() {
        // given — a single missing branch would ship entries that fail their own schema
        List<SystemOid> extensions = Arrays
                .stream(SystemOid.values())
                .filter(e -> e.getCategory() == OidCategory.CERTIFICATE_EXTENSION)
                .toList();
        // Without this the loop below would pass vacuously against an interfaces build that seeds none.
        assertThat(extensions).isNotEmpty();

        for (SystemOid entry : extensions) {

            // when
            CustomOidEntryDetailResponseDto dto = CustomOidEntryMapper.toDetailDto(entry);

            // then
            assertThat(dto.getAdditionalProperties())
                    .as("additionalProperties for %s", entry.getOid())
                    .isInstanceOf(CertificateExtensionOidPropertiesDto.class);
            CertificateExtensionOidPropertiesDto ext = (CertificateExtensionOidPropertiesDto) dto
                    .getAdditionalProperties();
            assertThat(ext.getDefaultCritical()).as("defaultCritical for %s", entry.getOid()).isNotNull();
            assertThat(ext.getValueEncoding()).as("valueEncoding for %s", entry.getOid()).isNotNull();
        }
    }

    @Test
    void systemRdnAttributeTypeStillCarriesCodeAndAltCodes() {
        // when
        CustomOidEntryDetailResponseDto dto = CustomOidEntryMapper.toDetailDto(SystemOid.SURNAME);

        // then
        assertThat(dto.getAdditionalProperties()).isInstanceOf(RdnAttributeTypeOidPropertiesDto.class);
        RdnAttributeTypeOidPropertiesDto rdn = (RdnAttributeTypeOidPropertiesDto) dto.getAdditionalProperties();
        assertThat(rdn.getCode()).isEqualTo("SN");
        assertThat(rdn.getAltCodes()).containsExactly("SURNAME");
    }

    @Test
    void systemExtendedKeyUsagePurposeHasNoAdditionalProperties() {
        // given — EKU purposes and generic identifiers carry nothing beyond the base fields
        // when / then
        assertThat(CustomOidEntryMapper.toDetailDto(SystemOid.TIME_STAMPING).getAdditionalProperties()).isNull();
    }
}
