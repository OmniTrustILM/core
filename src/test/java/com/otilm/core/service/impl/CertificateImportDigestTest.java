package com.otilm.core.service.impl;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.CertificateEntryKeyDestinationDto;
import com.otilm.api.model.client.certificate.CertificateImportEntryDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateImportDigestTest {

    private static final String REFERENCE = "0123456789abcdef".repeat(4);
    private static final String PROFILE = UUID.randomUUID().toString();

    @Test
    void of_isTheSameWhateverTheOrderOfTheAttributes() {
        // given
        CertificateImportEntryDto oneOrder = keyEntry(REFERENCE, PROFILE, "key", true,
                List.of(attribute("a", "1"), attribute("b", "2")), List.of(attribute("c", "3"), attribute("d", "4")));
        CertificateImportEntryDto otherOrder = keyEntry(REFERENCE, PROFILE, "key", true,
                List.of(attribute("b", "2"), attribute("a", "1")), List.of(attribute("d", "4"), attribute("c", "3")));

        // when
        String one = CertificateImportDigest.of(oneOrder, List.of(attribute("e", "5"), attribute("f", "6")));
        String other = CertificateImportDigest.of(otherOrder, List.of(attribute("f", "6"), attribute("e", "5")));

        // then
        assertThat(one).isEqualTo(other).matches("[0-9a-f]{64}");
    }

    @Test
    void of_differsWithEachTermOfTheEntry() {
        // given
        List<RequestAttribute> certificateAttributes = List.of(attribute("owner", "operations"));
        String base = CertificateImportDigest
                .of(keyEntry(REFERENCE, PROFILE, "key", false, List.of(attribute("label", "1")),
                        List.of(attribute("department", "sales"))), certificateAttributes);

        // when
        List<String> others = List
                .of(CertificateImportDigest
                        .of(keyEntry("f".repeat(64), PROFILE, "key", false, List.of(attribute("label", "1")),
                                List.of(attribute("department", "sales"))), certificateAttributes),
                        CertificateImportDigest
                                .of(keyEntry(REFERENCE, PROFILE, "another key", false, List.of(attribute("label", "1")),
                                        List.of(attribute("department", "sales"))), certificateAttributes),
                        CertificateImportDigest
                                .of(keyEntry(REFERENCE, PROFILE, null, false, List.of(attribute("label", "1")),
                                        List.of(attribute("department", "sales"))), certificateAttributes),
                        CertificateImportDigest
                                .of(keyEntry(REFERENCE, PROFILE, "key", true, List.of(attribute("label", "1")),
                                        List.of(attribute("department", "sales"))), certificateAttributes),
                        CertificateImportDigest
                                .of(keyEntry(REFERENCE, UUID.randomUUID().toString(), "key", false,
                                        List.of(attribute("label", "1")), List.of(attribute("department", "sales"))),
                                        certificateAttributes),
                        CertificateImportDigest
                                .of(keyEntry(REFERENCE, PROFILE, "key", false, List.of(attribute("label", "2")),
                                        List.of(attribute("department", "sales"))), certificateAttributes),
                        CertificateImportDigest
                                .of(keyEntry(REFERENCE, PROFILE, "key", false, List.of(attribute("label", "1")),
                                        List.of(attribute("department", "support"))), certificateAttributes),
                        CertificateImportDigest
                                .of(keyEntry(REFERENCE, PROFILE, "key", false, List.of(attribute("label", "1")),
                                        List.of(attribute("department", "sales"))),
                                        List.of(attribute("owner", "security"))),
                        CertificateImportDigest.of(certificateEntry(REFERENCE), certificateAttributes));

        // then
        assertThat(others).doesNotContain(base).doesNotHaveDuplicates();
    }

    /** A retry that leaves out what the first request stated as empty or false is the same import. */
    @Test
    void of_readsAbsentAttributesAndExportabilityAsTheirDefaults() {
        // given
        CertificateImportEntryDto stated = keyEntry(REFERENCE, PROFILE, "key", false, List.of(), List.of());
        CertificateImportEntryDto absent = keyEntry(REFERENCE, PROFILE, "key", null, null, null);

        // when
        String statedDigest = CertificateImportDigest.of(stated, List.of());
        String absentDigest = CertificateImportDigest.of(absent, null);

        // then
        assertThat(absentDigest).isEqualTo(statedDigest);
    }

    /** A retry that writes the profile's UUID in another case names the same profile, so it is the same import. */
    @Test
    void of_readsTheProfileAsTheUuidItNames() {
        // given
        CertificateImportEntryDto lowerCase = keyEntry(REFERENCE, PROFILE, "key", false, List.of(), List.of());
        CertificateImportEntryDto upperCase = keyEntry(REFERENCE, PROFILE.toUpperCase(Locale.ROOT), "key", false,
                List.of(), List.of());

        // when
        String lowerCaseDigest = CertificateImportDigest.of(lowerCase, List.of());
        String upperCaseDigest = CertificateImportDigest.of(upperCase, List.of());

        // then
        assertThat(upperCaseDigest).isEqualTo(lowerCaseDigest);
    }

    private static CertificateImportEntryDto keyEntry(String reference, String profile, String keyName,
            Boolean exportable, List<RequestAttribute> importAttributes, List<RequestAttribute> customAttributes) {
        CertificateEntryKeyDestinationDto destination = new CertificateEntryKeyDestinationDto();
        destination.setTokenProfileUuid(profile);
        destination.setKeyName(keyName);
        destination.setExportable(exportable);
        destination.setImportAttributes(importAttributes);
        destination.setCustomAttributes(customAttributes);
        CertificateImportEntryDto entry = certificateEntry(reference);
        entry.setKeyDestination(destination);
        return entry;
    }

    private static CertificateImportEntryDto certificateEntry(String reference) {
        CertificateImportEntryDto entry = new CertificateImportEntryDto();
        entry.setEntryReference(reference);
        entry.setImportId("import-" + UUID.randomUUID());
        return entry;
    }

    private static RequestAttribute attribute(String name, String value) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8)));
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3(value)));
        return attribute;
    }
}
