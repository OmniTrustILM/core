package com.otilm.core.mapper.signing;

import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.profile.workflow.timestamp.InternalTimestampSourceDto;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.CertificateTestData.DOCUMENT_SIGNING_OID;
import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static org.assertj.core.api.Assertions.assertThat;

class SigningProfileMapperContentSigningTest {

    private static final long DOCUMENT_SIZE_CAP = 5_242_880L;

    // ── Helpers ───────────────────────────────────────────────────────────────

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
        version.setDocumentSizeCap(DOCUMENT_SIZE_CAP);
        version.setRequireNonRepudiation(true);
        version.setRequiredExtendedKeyUsageOids(List.of(DOCUMENT_SIGNING_OID));
        return version;
    }

    // ── ToManagedContentSigningModel ──────────────────────────────────────────

    @Nested
    class ToManagedContentSigningModel {

        @Test
        void carriesTheLevelLadderFields() {
            // given
            var connectorUuid = UUID.randomUUID();
            var timestampSourceUuid = UUID.randomUUID();
            SigningProfileVersion version = aContentSigningVersion();
            version.setSignatureFormattingConnectorUuid(connectorUuid);
            version.setTimestampSourceProfileUuid(timestampSourceUuid);

            // when
            SigningProfileModel<ManagedContentSigningWorkflow, ?> model = SigningProfileMapper
                    .toManagedContentSigningModel(aHeader(), version, List.of(), List.of());

            // then
            assertThat(model.workflow().family()).isEqualTo(SignatureFamily.PADES);
            assertThat(model.workflow().maxLevel()).isEqualTo(SignatureLevel.TIMESTAMPED);
            assertThat(model.workflow().timestampSourceProfileUuid()).isEqualTo(timestampSourceUuid);
            assertThat(model.workflow().documentSizeCap()).isEqualTo(DOCUMENT_SIZE_CAP);
            assertThat(model.workflow().signatureFormattingConnectorUuid()).isEqualTo(connectorUuid);
            assertThat(model.workflow().certificatePurpose())
                    .isEqualTo(new CertificatePurposeRequirements(true, Set.of(DOCUMENT_SIGNING_OID)));
        }

        /** A row written before the certificate-purpose migration loads with a null OID list, not an empty one. */
        @Test
        void mapsToTheDefaultPurposeRule_whenALegacyVersionHasNoRequiredOids() {
            // given
            SigningProfileVersion version = aContentSigningVersion();
            version.setRequireNonRepudiation(false);
            version.setRequiredExtendedKeyUsageOids(null);

            // when
            SigningProfileModel<ManagedContentSigningWorkflow, ?> model = SigningProfileMapper
                    .toManagedContentSigningModel(aHeader(), version, List.of(), List.of());

            // then
            assertThat(model.workflow().certificatePurpose()).isEqualTo(CertificatePurposeRequirements.NONE);
        }

        /** Deny-all has no null-versus-empty split, so a stored null must not reach a reader as one. */
        @Test
        void mapsToAnEmptyAllowList_whenTheVersionStoresNull() {
            // given
            SigningProfileVersion version = aContentSigningVersion();
            version.setAllowedRequestParameterGroups(null);

            // when
            SigningProfileModel<ManagedContentSigningWorkflow, ?> model = SigningProfileMapper
                    .toManagedContentSigningModel(aHeader(), version, List.of(), List.of());

            // then
            assertThat(model.workflow().parameterPolicy().allowedGroups()).isEmpty();
        }
    }

    // ── ToDto ─────────────────────────────────────────────────────────────────

    @Nested
    class ToDto {

        @Test
        void carriesTheLevelLadderFields() {
            // given
            var timestampSourceUuid = UUID.randomUUID();
            SigningProfileVersion version = aContentSigningVersion();
            version.setTimestampSourceProfileUuid(timestampSourceUuid);

            // when
            SigningProfileDto dto = SigningProfileMapper
                    .toDto(aHeader(), version, List.of(), List.of(), List.of(), "ades-timestamps");

            // then
            ContentSigningWorkflowDto workflow = (ContentSigningWorkflowDto) dto.getWorkflow();
            assertThat(workflow.getFamily()).isEqualTo(SignatureFamily.PADES);
            assertThat(workflow.getMaxLevel()).isEqualTo(SignatureLevel.TIMESTAMPED);
            assertThat(workflow.getDocumentSizeCap()).isEqualTo(DOCUMENT_SIZE_CAP);
            assertThat(workflow.isRequireNonRepudiation()).isTrue();
            assertThat(workflow.getRequiredExtendedKeyUsageOids()).containsExactly(DOCUMENT_SIGNING_OID);
            assertThat(workflow.getTimestampSource())
                    .isInstanceOfSatisfying(InternalTimestampSourceDto.class,
                            source -> assertThat(source.signingProfile().getUuid())
                                    .isEqualTo(timestampSourceUuid.toString()));
        }

        /** The Settings UI shows the timestamp source by name, so a uuid-only reference reads as blank. */
        @Test
        void namesTheReferencedTimestampSource() {
            // given
            var timestampSourceName = "ades-timestamps";
            SigningProfileVersion version = aContentSigningVersion();
            version.setTimestampSourceProfileUuid(UUID.randomUUID());

            // when
            SigningProfileDto dto = SigningProfileMapper
                    .toDto(aHeader(), version, List.of(), List.of(), List.of(), timestampSourceName);

            // then
            assertThat(((ContentSigningWorkflowDto) dto.getWorkflow()).getTimestampSource())
                    .isInstanceOfSatisfying(InternalTimestampSourceDto.class,
                            source -> assertThat(source.signingProfile().getName()).isEqualTo(timestampSourceName));
        }

        /** A reference whose profile no longer resolves still answers the uuid rather than failing the read. */
        @Test
        void keepsTheTimestampSourceUuid_whenItsNameDoesNotResolve() {
            // given
            var timestampSourceUuid = UUID.randomUUID();
            SigningProfileVersion version = aContentSigningVersion();
            version.setTimestampSourceProfileUuid(timestampSourceUuid);

            // when
            SigningProfileDto dto = SigningProfileMapper
                    .toDto(aHeader(), version, List.of(), List.of(), List.of(), null);

            // then
            assertThat(((ContentSigningWorkflowDto) dto.getWorkflow()).getTimestampSource())
                    .isInstanceOfSatisfying(InternalTimestampSourceDto.class, source -> {
                        assertThat(source.signingProfile().getUuid()).isEqualTo(timestampSourceUuid.toString());
                        assertThat(source.signingProfile().getName()).isNull();
                    });
        }

        @Test
        void omitsTheTimestampSource_whenNoneIsReferenced() {
            // given
            SigningProfileVersion version = aContentSigningVersion();
            version.setTimestampSourceProfileUuid(null);

            // when
            SigningProfileDto dto = SigningProfileMapper
                    .toDto(aHeader(), version, List.of(), List.of(), List.of(), null);

            // then
            assertThat(((ContentSigningWorkflowDto) dto.getWorkflow()).getTimestampSource()).isNull();
        }

        @Test
        void carriesTheAllowListAndTheTypedDefaults() {
            // given — the version stores the group as its code
            var allowedGroup = SignatureParameterGroup.SIGNATURE_CONTEXT;
            SigningProfileVersion version = aContentSigningVersion();
            version.setAllowedRequestParameterGroups(new ArrayList<>(List.of(allowedGroup.getCode())));
            version.setDefaultSignatureParameters(aPadesParameters().withReason("Contract approval").build());

            // when
            SigningProfileDto dto = SigningProfileMapper
                    .toDto(aHeader(), version, List.of(), List.of(), List.of(), null);

            // then
            ContentSigningWorkflowDto workflow = (ContentSigningWorkflowDto) dto.getWorkflow();
            assertThat(workflow.getAllowedRequestParameterGroups()).containsExactly(allowedGroup);
            assertThat(workflow.getDefaultSignatureParameters()).isInstanceOf(PadesSignatureParametersDto.class);
        }
    }
}
