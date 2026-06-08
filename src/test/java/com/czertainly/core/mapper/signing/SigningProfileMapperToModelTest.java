package com.czertainly.core.mapper.signing;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.core.signing.SigningProtocol;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.SigningRecordPolicyModel;
import com.czertainly.core.model.signing.scheme.ManagedSigning;
import com.czertainly.core.model.signing.scheme.OneTimeKeyManagedSigning;
import com.czertainly.core.model.signing.scheme.StaticKeyManagedSigning;
import com.czertainly.core.model.signing.workflow.ManagedTimestampingWorkflow;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningProfileMapperToModelTest {

    private static final UUID PROFILE_UUID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID TQC_UUID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final UUID FORMATTER_UUID = UUID.fromString("33333333-3333-3333-3333-333333333333");
    private static final UUID CERT_UUID = UUID.fromString("44444444-4444-4444-4444-444444444444");
    private static final UUID RA_UUID = UUID.fromString("55555555-5555-5555-5555-555555555555");
    private static final UUID TOKEN_UUID = UUID.fromString("66666666-6666-6666-6666-666666666666");
    private static final UUID CSR_TEMPLATE_UUID = UUID.fromString("77777777-7777-7777-7777-777777777777");
    private static final UUID TSP_UUID = UUID.fromString("88888888-8888-8888-8888-888888888888");

    @Test
    void toManagedTimestampingModel_staticKey_carriesUuidReferences() {
        SigningProfile header = newHeader();
        SigningProfileVersion version = newTimestampingVersion();
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setCertificateUuid(CERT_UUID);

        SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

        assertEquals(PROFILE_UUID, model.uuid());
        assertEquals("profile-x", model.name());
        assertEquals(1, model.version());
        assertTrue(model.enabled());
        assertEquals(List.of(SigningProtocol.TSP), model.enabledProtocols());

        StaticKeyManagedSigning scheme = assertInstanceOf(StaticKeyManagedSigning.class, model.signingScheme());
        assertEquals(CERT_UUID, scheme.certificateUuid());

        ManagedTimestampingWorkflow wf = model.workflow();
        assertEquals(TQC_UUID, wf.timeQualityConfigurationUuid());
        assertEquals(FORMATTER_UUID, wf.signatureFormatterConnectorUuid());
        assertEquals("1.2.3.4.5", wf.defaultPolicyId());
        assertEquals(List.of(DigestAlgorithm.SHA_256), wf.allowedDigestAlgorithms());
        assertFalse(wf.isQualifiedTimestamp());
    }

    @Test
    void toManagedTimestampingModel_oneTimeKey_carriesUuidReferences() {
        SigningProfile header = newHeader();
        SigningProfileVersion version = newTimestampingVersion();
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.ONE_TIME_KEY);
        version.setRaProfileUuid(RA_UUID);
        version.setTokenProfileUuid(TOKEN_UUID);
        version.setCsrTemplateUuid(CSR_TEMPLATE_UUID);

        SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

        OneTimeKeyManagedSigning scheme = assertInstanceOf(OneTimeKeyManagedSigning.class, model.signingScheme());
        assertEquals(RA_UUID, scheme.raProfileUuid());
        assertEquals(TOKEN_UUID, scheme.tokenProfileUuid());
        assertEquals(CSR_TEMPLATE_UUID, scheme.csrTemplateUuid());
    }

    @Test
    void toManagedTimestampingModel_withoutTspProfile_hasNoEnabledProtocols() {
        SigningProfile header = newHeader();
        header.setTspProfileUuid(null);
        SigningProfileVersion version = newTimestampingVersion();
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setCertificateUuid(CERT_UUID);

        SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

        assertTrue(model.enabledProtocols().isEmpty());
    }

    @Test
    void toManagedTimestampingModel_nullTimeQualityConfiguration_carriesNullUuid() {
        SigningProfile header = newHeader();
        header.setTimeQualityConfigurationUuid(null);
        SigningProfileVersion version = newTimestampingVersion();
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setCertificateUuid(CERT_UUID);

        SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

        assertNull(model.workflow().timeQualityConfigurationUuid());
    }

    @Test
    void toManagedTimestampingModel_carriesRecordPolicy_allFieldsFromVersion() {
        // given — distinct values so a transposed field would surface; T/F/T/F/T disambiguates the flags
        var retentionDays = 30;
        var persistenceMode = SigningRecordPersistenceMode.IMMEDIATE;
        SigningProfile header = newHeader();
        SigningProfileVersion version = newTimestampingVersion();
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setCertificateUuid(CERT_UUID);
        version.setRetentionDays(retentionDays);
        version.setDeleteAfterRetrieval(true);
        version.setPersistenceMode(persistenceMode);
        version.setRecordRequestMetadata(false);
        version.setRecordSignature(true);
        version.setRecordSignedDocument(false);
        version.setRecordDtbs(true);

        // when
        SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

        // then
        SigningRecordPolicyModel policy = model.recordPolicy();
        assertFalse(policy.recordRequestMetadata());
        assertTrue(policy.recordSignature());
        assertFalse(policy.recordSignedDocument());
        assertTrue(policy.recordDtbs());
        assertEquals(retentionDays, policy.retentionDays());
        assertTrue(policy.deleteAfterRetrieval());
        assertEquals(persistenceMode, policy.persistenceMode());
    }

    @Test
    void toManagedTimestampingModel_carriesRecordPolicy_nullRetentionDays() {
        // given
        SigningProfile header = newHeader();
        SigningProfileVersion version = newTimestampingVersion();
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setCertificateUuid(CERT_UUID);
        version.setRetentionDays(null);

        // when
        SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

        // then
        assertNull(model.recordPolicy().retentionDays());
    }

    @Test
    void toManagedTimestampingModel_throwsOnNonTimestampingWorkflow() {
        SigningProfile header = newHeader();
        SigningProfileVersion version = newTimestampingVersion();
        version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        List<RequestAttribute> empty = List.of();

        assertThrows(IllegalArgumentException.class,
                () -> SigningProfileMapper.toManagedTimestampingModel(header, version, empty, empty));
    }

    @Test
    void toManagedTimestampingModel_throwsOnDelegatedScheme() {
        SigningProfile header = newHeader();
        SigningProfileVersion version = newTimestampingVersion();
        version.setSigningScheme(SigningScheme.DELEGATED);
        List<RequestAttribute> empty = List.of();

        assertThrows(IllegalArgumentException.class,
                () -> SigningProfileMapper.toManagedTimestampingModel(header, version, empty, empty));
    }

    @Test
    void toManagedTimestampingModel_throwsOnManagedWithoutManagedSigningType() {
        SigningProfile header = newHeader();
        SigningProfileVersion version = newTimestampingVersion();
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(null);
        List<RequestAttribute> empty = List.of();

        assertThrows(IllegalStateException.class,
                () -> SigningProfileMapper.toManagedTimestampingModel(header, version, empty, empty));
    }

    private static SigningProfile newHeader() {
        SigningProfile p = new SigningProfile();
        p.setUuid(PROFILE_UUID);
        p.setName("profile-x");
        p.setDescription("desc");
        p.setEnabled(true);
        p.setTimeQualityConfigurationUuid(TQC_UUID);
        p.setTspProfileUuid(TSP_UUID);
        return p;
    }

    private static SigningProfileVersion newTimestampingVersion() {
        SigningProfileVersion v = new SigningProfileVersion();
        v.setVersion(1);
        v.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        v.setSignatureFormatterConnectorUuid(FORMATTER_UUID);
        v.setQualifiedTimestamp(false);
        v.setDefaultPolicyId("1.2.3.4.5");
        v.setAllowedPolicyIds(List.of("1.2.3.4.5"));
        v.setAllowedDigestAlgorithms(List.of(DigestAlgorithm.SHA_256.getCode()));
        v.setValidateTokenSignature(false);
        return v;
    }
}
