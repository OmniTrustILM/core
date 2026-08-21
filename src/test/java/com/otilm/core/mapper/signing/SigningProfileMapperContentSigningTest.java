package com.otilm.core.mapper.signing;

import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.profile.workflow.timestamp.InternalTimestampSourceDto;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SigningProfileMapperContentSigningTest {

    @Test
    void contentSigningModelCarriesTheLevelLadderFields() {
        // given
        UUID connectorUuid = UUID.randomUUID();
        UUID timestampSourceUuid = UUID.randomUUID();
        SigningProfile header = new SigningProfile();
        header.setUuid(UUID.randomUUID());
        header.setName("pades-profile");
        header.setEnabled(true);

        SigningProfileVersion version = new SigningProfileVersion();
        version.setVersion(3);
        version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setCertificateUuid(UUID.randomUUID());
        version.setSignatureFormattingConnectorUuid(connectorUuid);
        version.setSignatureFamily(SignatureFamily.PADES);
        version.setMaxSignatureLevel(SignatureLevel.TIMESTAMPED);
        version.setTimestampSourceProfileUuid(timestampSourceUuid);
        version.setDocumentSizeCap(5_242_880L);

        // when
        SigningProfileModel<ManagedContentSigningWorkflow, ?> model = SigningProfileMapper
                .toManagedContentSigningModel(header, version, List.of(), List.of());

        // then
        assertThat(model.workflow().family()).isEqualTo(SignatureFamily.PADES);
        assertThat(model.workflow().maxLevel()).isEqualTo(SignatureLevel.TIMESTAMPED);
        assertThat(model.workflow().timestampSourceProfileUuid()).isEqualTo(timestampSourceUuid);
        assertThat(model.workflow().documentSizeCap()).isEqualTo(5_242_880L);
        assertThat(model.workflow().signatureFormattingConnectorUuid()).isEqualTo(connectorUuid);
    }

    @Test
    void contentSigningDtoCarriesTheLevelLadderFields() {
        // given
        UUID timestampSourceUuid = UUID.randomUUID();
        SigningProfileVersion version = aContentSigningVersion();
        version.setTimestampSourceProfileUuid(timestampSourceUuid);

        // when
        SigningProfileDto dto = SigningProfileMapper
                .toDto(aHeader(), version, List.of(), List.of(), List.of(), "ades-timestamps");

        // then
        ContentSigningWorkflowDto workflow = (ContentSigningWorkflowDto) dto.getWorkflow();
        assertThat(workflow.getFamily()).isEqualTo(SignatureFamily.PADES);
        assertThat(workflow.getMaxLevel()).isEqualTo(SignatureLevel.TIMESTAMPED);
        assertThat(workflow.getDocumentSizeCap()).isEqualTo(5_242_880L);
        assertThat(workflow.getTimestampSource())
                .isInstanceOfSatisfying(InternalTimestampSourceDto.class,
                        source -> assertThat(source.signingProfile().getUuid())
                                .isEqualTo(timestampSourceUuid.toString()));
    }

    /** The Settings UI shows the timestamp source by name, so a uuid-only reference reads as blank. */
    @Test
    void contentSigningDtoNamesTheReferencedTimestampSource() {
        // given
        SigningProfileVersion version = aContentSigningVersion();
        version.setTimestampSourceProfileUuid(UUID.randomUUID());

        // when
        SigningProfileDto dto = SigningProfileMapper
                .toDto(aHeader(), version, List.of(), List.of(), List.of(), "ades-timestamps");

        // then
        assertThat(((ContentSigningWorkflowDto) dto.getWorkflow()).getTimestampSource())
                .isInstanceOfSatisfying(InternalTimestampSourceDto.class,
                        source -> assertThat(source.signingProfile().getName()).isEqualTo("ades-timestamps"));
    }

    /** A reference whose profile no longer resolves still answers the uuid rather than failing the read. */
    @Test
    void contentSigningDtoKeepsTheTimestampSourceUuidWhenItsNameDoesNotResolve() {
        // given
        UUID timestampSourceUuid = UUID.randomUUID();
        SigningProfileVersion version = aContentSigningVersion();
        version.setTimestampSourceProfileUuid(timestampSourceUuid);

        // when
        SigningProfileDto dto = SigningProfileMapper.toDto(aHeader(), version, List.of(), List.of(), List.of(), null);

        // then
        assertThat(((ContentSigningWorkflowDto) dto.getWorkflow()).getTimestampSource())
                .isInstanceOfSatisfying(InternalTimestampSourceDto.class, source -> {
                    assertThat(source.signingProfile().getUuid()).isEqualTo(timestampSourceUuid.toString());
                    assertThat(source.signingProfile().getName()).isNull();
                });
    }

    @Test
    void contentSigningDtoOmitsTheTimestampSourceWhenNoneIsReferenced() {
        // given
        SigningProfileVersion version = aContentSigningVersion();
        version.setTimestampSourceProfileUuid(null);

        // when
        SigningProfileDto dto = SigningProfileMapper.toDto(aHeader(), version, List.of(), List.of(), List.of(), null);

        // then
        assertThat(((ContentSigningWorkflowDto) dto.getWorkflow()).getTimestampSource()).isNull();
    }

    private static SigningProfile aHeader() {
        SigningProfile header = new SigningProfile();
        header.setUuid(UUID.randomUUID());
        header.setName("pades-profile");
        header.setEnabled(true);
        return header;
    }

    private static SigningProfileVersion aContentSigningVersion() {
        SigningProfileVersion version = new SigningProfileVersion();
        version.setVersion(3);
        version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setSignatureFormattingConnectorUuid(UUID.randomUUID());
        version.setSignatureFamily(SignatureFamily.PADES);
        version.setMaxSignatureLevel(SignatureLevel.TIMESTAMPED);
        version.setDocumentSizeCap(5_242_880L);
        return version;
    }
}
