package com.czertainly.core.model.signing.resolved;

import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.core.signing.SigningProtocol;
import com.czertainly.core.dao.entity.Certificate;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResolvedSigningProfileTest {

    private static final UUID PROFILE_UUID = UUID.fromString("11111111-1111-1111-1111-111111111111");

    @Test
    void resolvedManagedTimestampingProfile_carriesAllFields_andReportsTimestampingWorkflowType() {
        ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                new Certificate(), List.of(), List.of());

        ResolvedManagedTimestampingProfile profile = new ResolvedManagedTimestampingProfile(
                PROFILE_UUID,
                "profile-x",
                "desc",
                3,
                true,
                List.of(SigningProtocol.TSP),
                Boolean.TRUE,
                "1.2.3.4.5",
                List.of("1.2.3.4.5", "1.2.3.4.6"),
                List.of(DigestAlgorithm.SHA_256),
                Boolean.FALSE,
                List.of(),
                null,
                null,
                scheme);

        assertEquals(PROFILE_UUID, profile.uuid());
        assertEquals("profile-x", profile.name());
        assertEquals("desc", profile.description());
        assertEquals(3, profile.version());
        assertTrue(profile.enabled());
        assertEquals(List.of(SigningProtocol.TSP), profile.enabledProtocols());
        assertEquals(Boolean.TRUE, profile.isQualifiedTimestamp());
        assertEquals("1.2.3.4.5", profile.defaultPolicyId());
        assertEquals(List.of("1.2.3.4.5", "1.2.3.4.6"), profile.allowedPolicyIds());
        assertEquals(List.of(DigestAlgorithm.SHA_256), profile.allowedDigestAlgorithms());
        assertEquals(Boolean.FALSE, profile.validateTokenSignature());
        assertNotNull(profile.signatureFormatterConnectorAttributes());
        assertNull(profile.timeQualityConfiguration());
        assertNull(profile.signatureFormatterConnector());
        assertSame(scheme, profile.resolvedScheme());

        assertEquals(SigningWorkflowType.TIMESTAMPING, profile.workflowType());
    }

    @Test
    void resolvedManagedTimestampingProfile_isResolvedSigningProfile() {
        ResolvedSigningProfile profile = new ResolvedManagedTimestampingProfile(
                PROFILE_UUID, "n", null, 1, false, List.of(),
                false, null, List.of(), List.of(), null,
                List.of(), null, null,
                new ResolvedStaticKeyManagedSigning(new Certificate(), List.of(), List.of()));

        assertInstanceOf(ResolvedManagedTimestampingProfile.class, profile);
        assertEquals(SigningWorkflowType.TIMESTAMPING, profile.workflowType());
    }

    @Test
    void resolvedStaticKeyManagedSigning_carriesCertificateAndChain() {
        Certificate cert = new Certificate();
        ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(
                cert, List.of(), List.of());

        assertSame(cert, scheme.certificate());
        assertNotNull(scheme.chain());
        assertNotNull(scheme.signingOperationAttributes());
    }

    @Test
    void resolvedStaticKeyManagedSigning_isResolvedManagedScheme() {
        ResolvedManagedScheme scheme = new ResolvedStaticKeyManagedSigning(
                new Certificate(), List.of(), List.of());

        assertInstanceOf(ResolvedStaticKeyManagedSigning.class, scheme);
    }
}
