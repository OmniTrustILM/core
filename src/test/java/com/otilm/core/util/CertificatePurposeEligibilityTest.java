package com.otilm.core.util;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.otilm.api.model.core.certificate.CertificateSubjectType;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static com.otilm.core.util.CertificateTestData.DOCUMENT_SIGNING_OID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The certificate-purpose rule for the content- and raw-signing workflows.
 */
class CertificatePurposeEligibilityTest {

    private static final String EMAIL_PROTECTION_OID = "1.3.6.1.5.5.7.3.4";

    private static final List<CryptographicKeyItemOperationModel> SIGNING_KEY_ITEMS = List
            .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA));

    // ── the default rule ─────────────────────────────────────────────────────

    @ParameterizedTest
    @EnumSource(value = SigningWorkflowType.class, names = {"CONTENT_SIGNING", "RAW_SIGNING"})
    void acceptsDigitalSignatureAlone(SigningWorkflowType workflowType) {
        assertThat(isAcceptable(aCertificate(CertificateKeyUsage.DIGITAL_SIGNATURE), workflowType,
                CertificatePurposeRequirements.NONE)).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = SigningWorkflowType.class, names = {"CONTENT_SIGNING", "RAW_SIGNING"})
    void acceptsNonRepudiationAlone(SigningWorkflowType workflowType) {
        // ETSI EN 319 412-2: qualified signing certificates commonly carry nonRepudiation and nothing else.
        assertThat(isAcceptable(aCertificate(CertificateKeyUsage.NON_REPUDIATION), workflowType,
                CertificatePurposeRequirements.NONE)).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = SigningWorkflowType.class, names = {"CONTENT_SIGNING", "RAW_SIGNING"})
    void refusesACertificateCarryingNoKeyUsageExtension(SigningWorkflowType workflowType) {
        assertThat(isAcceptable(aCertificate(), workflowType, CertificatePurposeRequirements.NONE)).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = SigningWorkflowType.class, names = {"CONTENT_SIGNING", "RAW_SIGNING"})
    void refusesAKeyUsageThatCannotSign(SigningWorkflowType workflowType) {
        assertThat(isAcceptable(aCertificate(CertificateKeyUsage.KEY_ENCIPHERMENT), workflowType,
                CertificatePurposeRequirements.NONE)).isFalse();
    }

    @Test
    void acceptsASelfSignedEndEntity() {
        SigningCertificate certificate = SigningCertificateBuilder
                .aSigningCertificate()
                .keyUsage(CertificateKeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsageOids(List.of())
                .subjectType(CertificateSubjectType.SELF_SIGNED_END_ENTITY)
                .build();

        assertThat(isAcceptable(certificate, SigningWorkflowType.CONTENT_SIGNING, CertificatePurposeRequirements.NONE))
                .isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = CertificateSubjectType.class, names = {"ROOT_CA", "INTERMEDIATE_CA"})
    void refusesACaCertificate(CertificateSubjectType subjectType) {
        SigningCertificate certificate = SigningCertificateBuilder
                .aSigningCertificate()
                .keyUsage(CertificateKeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsageOids(List.of())
                .subjectType(subjectType)
                .build();

        assertThat(isAcceptable(certificate, SigningWorkflowType.CONTENT_SIGNING, CertificatePurposeRequirements.NONE))
                .isFalse();
    }

    @Test
    void leavesTheTimestampingRuleAlone() {
        SigningCertificate tsaCertificateWithoutKeyUsage = SigningCertificateBuilder.valid();

        assertThat(isAcceptable(tsaCertificateWithoutKeyUsage, SigningWorkflowType.TIMESTAMPING,
                CertificatePurposeRequirements.NONE)).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = SigningWorkflowType.class, names = {"CONTENT_SIGNING", "RAW_SIGNING"})
    void refusesACertificateWhoseOnlyExtendedKeyUsageIsTimestamping(SigningWorkflowType workflowType) {
        // RFC 3161 reserves this certificate for a TSA, so it may not sign content.
        SigningCertificate certificate = aSigningCertificateWithEku(SystemOid.TIME_STAMPING.getOid());

        assertThat(isAcceptable(certificate, workflowType, CertificatePurposeRequirements.NONE)).isFalse();
    }

    @Test
    void acceptsACertificateCarryingTimestampingAlongsideAnotherPurpose() {
        SigningCertificate certificate = aSigningCertificateWithEku(SystemOid.TIME_STAMPING.getOid(),
                DOCUMENT_SIGNING_OID);

        assertThat(isAcceptable(certificate, SigningWorkflowType.CONTENT_SIGNING, CertificatePurposeRequirements.NONE))
                .isTrue();
    }

    // ── constraint construction ──────────────────────────────────────────────

    @Test
    void aNullRequiredOidCollectionYieldsTheDefaultPurposeRule() {
        assertThat(CertificatePurposeRequirements.of(false, null)).isEqualTo(CertificatePurposeRequirements.NONE);
    }

    @Test
    void theRequiredOidSetIsCopiedAndUnmodifiable() {
        List<String> mutable = new ArrayList<>(List.of(DOCUMENT_SIGNING_OID));

        CertificatePurposeRequirements purpose = CertificatePurposeRequirements.of(false, mutable);
        mutable.clear();

        Set<String> requiredOids = purpose.requiredExtendedKeyUsageOids();

        assertThat(requiredOids).containsExactly(DOCUMENT_SIGNING_OID);
        assertThatThrownBy(() -> requiredOids.add("1.2.3")).isInstanceOf(UnsupportedOperationException.class);
    }

    // ── requireNonRepudiation ────────────────────────────────────────────────

    @Test
    void refusesDigitalSignatureAloneWhenTheProfileDemandsNonRepudiation() {
        assertThat(isAcceptable(aCertificate(CertificateKeyUsage.DIGITAL_SIGNATURE),
                SigningWorkflowType.CONTENT_SIGNING, requireNonRepudiation())).isFalse();
    }

    @Test
    void acceptsNonRepudiationWhenTheProfileDemandsIt() {
        assertThat(isAcceptable(aCertificate(CertificateKeyUsage.NON_REPUDIATION), SigningWorkflowType.CONTENT_SIGNING,
                requireNonRepudiation())).isTrue();
    }

    @Test
    void acceptsBothBitsWhenTheProfileDemandsNonRepudiation() {
        assertThat(
                isAcceptable(aCertificate(CertificateKeyUsage.DIGITAL_SIGNATURE, CertificateKeyUsage.NON_REPUDIATION),
                        SigningWorkflowType.CONTENT_SIGNING, requireNonRepudiation()))
                .isTrue();
    }

    // ── requiredExtendedKeyUsageOids ─────────────────────────────────────────

    @Test
    void acceptsACertificateCarryingEveryRequiredOid() {
        SigningCertificate certificate = aSigningCertificateWithEku(DOCUMENT_SIGNING_OID, EMAIL_PROTECTION_OID);

        assertThat(isAcceptable(certificate, SigningWorkflowType.CONTENT_SIGNING,
                requireExtendedKeyUsage(DOCUMENT_SIGNING_OID))).isTrue();
    }

    @Test
    void refusesACertificateMissingOneRequiredOid() {
        SigningCertificate certificate = aSigningCertificateWithEku(DOCUMENT_SIGNING_OID);

        assertThat(isAcceptable(certificate, SigningWorkflowType.CONTENT_SIGNING,
                requireExtendedKeyUsage(DOCUMENT_SIGNING_OID, EMAIL_PROTECTION_OID))).isFalse();
    }

    @Test
    void refusesACertificateCarryingNoExtendedKeyUsageAtAll() {
        SigningCertificate certificate = aSigningCertificateWithEku();

        assertThat(isAcceptable(certificate, SigningWorkflowType.CONTENT_SIGNING,
                requireExtendedKeyUsage(DOCUMENT_SIGNING_OID))).isFalse();
    }

    @Test
    void ignoresExtendedKeyUsageWhenTheProfileRequiresNoOid() {
        SigningCertificate certificate = aSigningCertificateWithEku();

        assertThat(isAcceptable(certificate, SigningWorkflowType.CONTENT_SIGNING, CertificatePurposeRequirements.NONE))
                .isTrue();
    }

    // ── describing why a certificate was refused ─────────────────────────────

    @Test
    void namesTheKeyUsageTheProfileDemands() {
        Certificate certificate = aCertificateEntity(CertificateKeyUsage.DIGITAL_SIGNATURE);

        assertThat(CertificateEligibilityUtil
                .describeSigningPurposeMismatch(certificate, SigningWorkflowType.CONTENT_SIGNING,
                        requireNonRepudiation()))
                .hasValueSatisfying(reason -> assertThat(reason).contains("nonRepudiation"));
    }

    @Test
    void namesTheMissingExtendedKeyUsageOids() {
        Certificate certificate = aCertificateEntity(CertificateKeyUsage.DIGITAL_SIGNATURE, DOCUMENT_SIGNING_OID);

        assertThat(CertificateEligibilityUtil
                .describeSigningPurposeMismatch(certificate, SigningWorkflowType.CONTENT_SIGNING,
                        requireExtendedKeyUsage(EMAIL_PROTECTION_OID)))
                .hasValueSatisfying(reason -> assertThat(reason).contains(EMAIL_PROTECTION_OID));
    }

    @Test
    void namesACaSubjectType() {
        Certificate certificate = aCertificateEntity(CertificateKeyUsage.DIGITAL_SIGNATURE);
        certificate.setSubjectType(CertificateSubjectType.INTERMEDIATE_CA);

        assertThat(CertificateEligibilityUtil
                .describeSigningPurposeMismatch(certificate, SigningWorkflowType.CONTENT_SIGNING,
                        CertificatePurposeRequirements.NONE))
                .hasValueSatisfying(reason -> assertThat(reason).contains("end entity"));
    }

    @Test
    void describesNoMismatchForAnAcceptableCertificate() {
        Certificate certificate = aCertificateEntity(CertificateKeyUsage.NON_REPUDIATION, DOCUMENT_SIGNING_OID);

        assertThat(CertificateEligibilityUtil
                .describeSigningPurposeMismatch(certificate, SigningWorkflowType.CONTENT_SIGNING,
                        requireNonRepudiation()))
                .isEmpty();
    }

    @Test
    void describesNoMismatchForTimestamping() {
        Certificate certificate = aCertificateEntity(CertificateKeyUsage.KEY_ENCIPHERMENT);

        assertThat(CertificateEligibilityUtil
                .describeSigningPurposeMismatch(certificate, SigningWorkflowType.TIMESTAMPING,
                        CertificatePurposeRequirements.NONE))
                .isEmpty();
    }

    @Test
    void namesATimestampingOnlyExtendedKeyUsage() {
        Certificate certificate = aCertificateEntity(CertificateKeyUsage.DIGITAL_SIGNATURE,
                SystemOid.TIME_STAMPING.getOid());

        assertThat(CertificateEligibilityUtil
                .describeSigningPurposeMismatch(certificate, SigningWorkflowType.CONTENT_SIGNING,
                        CertificatePurposeRequirements.NONE))
                .hasValueSatisfying(reason -> assertThat(reason).contains("timestamping certificate"));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static Certificate aCertificateEntity(CertificateKeyUsage keyUsage, String... extendedKeyUsageOids) {
        Certificate certificate = new Certificate();
        certificate.setUsage(List.of(keyUsage));
        certificate
                .setExtendedKeyUsage(extendedKeyUsageOids.length == 0
                        ? null
                        : MetaDefinitions.serializeArrayString(List.of(extendedKeyUsageOids)));
        return certificate;
    }

    private static boolean isAcceptable(SigningCertificate certificate, SigningWorkflowType workflowType,
            CertificatePurposeRequirements purpose) {
        return CertificateEligibilityUtil
                .isCertificateDigitalSigningAcceptable(certificate, SIGNING_KEY_ITEMS, workflowType, false, purpose);
    }

    private static SigningCertificate aCertificate(CertificateKeyUsage... keyUsages) {
        return SigningCertificateBuilder
                .aSigningCertificate()
                .keyUsage(keyUsages)
                .extendedKeyUsageOids(List.of())
                .build();
    }

    private static SigningCertificate aSigningCertificateWithEku(String... oids) {
        return SigningCertificateBuilder
                .aSigningCertificate()
                .keyUsage(CertificateKeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsageOids(List.of(oids))
                .build();
    }

    private static CertificatePurposeRequirements requireNonRepudiation() {
        return new CertificatePurposeRequirements(true, Set.of());
    }

    private static CertificatePurposeRequirements requireExtendedKeyUsage(String... oids) {
        return new CertificatePurposeRequirements(false, Set.of(oids));
    }
}
