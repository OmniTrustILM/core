package com.otilm.core.service.scep.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ScepException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.scep.message.ScepRequest;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.UUID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ScepServiceImpl#authenticateRenewal}, the positive renewal classification that decides whether
 * a request may enroll without the profile's challenge password. The waiver requires the request to prove possession of
 * an existing certificate's key (RFC 8894 §3.3.1.2), so an unresolvable or foreign signer certificate must never earn
 * it.
 */
class ScepServiceImplRenewalAuthenticationTest {

    private static final String SUBJECT_DN = "CN=renewal-client";
    private static final UUID RA_PROFILE_UUID = UUID.randomUUID();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private ScepServiceImpl service;
    private ScepProfile profile;
    private CertificateInternalService certificateService;
    private KeyPair clientKeyPair;
    private X509Certificate clientCertificate;

    @BeforeEach
    void setUp() throws Exception {
        service = new ScepServiceImpl();
        profile = mock(ScepProfile.class);
        certificateService = mock(CertificateInternalService.class);

        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(RA_PROFILE_UUID);

        ReflectionTestUtils.setField(service, "scepProfile", profile);
        ReflectionTestUtils.setField(service, "raProfile", raProfile);
        ReflectionTestUtils.setField(service, "certificateService", certificateService);

        when(profile.getRenewalThreshold()).thenReturn(30);

        clientKeyPair = generateRsaKeyPair();
        clientCertificate = selfSignedCertificate(clientKeyPair, SUBJECT_DN);
    }

    @Test
    void noSignerCertificate_isNotARenewal() throws Exception {
        ScepRequest request = mock(ScepRequest.class);
        when(request.getSignerCertificate()).thenReturn(null);

        assertFalse(service.authenticateRenewal(request));
    }

    @Test
    void signerCertificateNotInInventory_isNotARenewal() throws Exception {
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenThrow(new NotFoundException(Certificate.class, "fingerprint"));

        assertFalse(service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    @Test
    void resolvedCertificateWithVerifiedSignature_isAnAuthenticatedRenewal() throws Exception {
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));

        assertTrue(service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    @Test
    void failedSignatureVerification_rejectedWithBadMessageCheck() throws Exception {
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));

        ScepException thrown = assertThrows(ScepException.class,
                () -> service.authenticateRenewal(renewalRequest(SUBJECT_DN, false)));
        assertEquals(FailInfo.BAD_MESSAGE_CHECK, thrown.getFailInfo());
    }

    /**
     * The signer certificate belongs to a different RA profile, so it is not entitled to this SCEP profile's enrollment
     * without the shared secret: renewal policy still applies, but the challenge password waiver is withheld.
     */
    @Test
    void certificateOfAnotherRaProfile_doesNotEarnTheWaiver() throws Exception {
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(UUID.randomUUID()));

        assertFalse(service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    /**
     * The waiver must never be earned by a certificate that is no longer usable. With no renewal threshold configured —
     * the default — `checkRenewalTimeframe` skips its revoked/expired branch entirely, so the state gate has to stand
     * on its own.
     */
    @Test
    void revokedCertificate_isRejected_withDefaultRenewalThreshold() throws Exception {
        when(profile.getRenewalThreshold()).thenReturn(null);
        Certificate revoked = inventoryCertificate(RA_PROFILE_UUID);
        revoked.setState(CertificateState.REVOKED);
        revoked.setValidationStatus(CertificateValidationStatus.REVOKED);
        when(certificateService.getCertificateEntityByFingerprint(any())).thenReturn(revoked);

        ScepException thrown = assertThrows(ScepException.class,
                () -> service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
        assertEquals(FailInfo.BAD_REQUEST, thrown.getFailInfo());
    }

    @Test
    void expiredCertificate_isRejected_withDefaultRenewalThreshold() throws Exception {
        when(profile.getRenewalThreshold()).thenReturn(null);
        Certificate expired = inventoryCertificate(RA_PROFILE_UUID);
        expired.setValidationStatus(CertificateValidationStatus.EXPIRED);
        when(certificateService.getCertificateEntityByFingerprint(any())).thenReturn(expired);

        assertThrows(ScepException.class, () -> service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    @Test
    void healthyCertificate_isAnAuthenticatedRenewal_withDefaultRenewalThreshold() throws Exception {
        when(profile.getRenewalThreshold()).thenReturn(null);
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));

        assertTrue(service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    /**
     * A nullable validation status must not crash the renewal-window check on the configured-threshold branch: the
     * renewable-state gate lets a null status through, so the timeframe policy must not dereference it.
     */
    @Test
    void certificateWithoutValidationStatus_isAnAuthenticatedRenewal() throws Exception {
        Certificate uncheckedCertificate = inventoryCertificate(RA_PROFILE_UUID);
        uncheckedCertificate.setValidationStatus(null);
        when(certificateService.getCertificateEntityByFingerprint(any())).thenReturn(uncheckedCertificate);

        assertTrue(service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    /**
     * A validation status of FAILED means the platform could not reach a CRL or OCSP responder. That is not evidence
     * against the certificate, so the renewal is not rejected — but it is not evidence for it either, so the shared
     * secret is required instead of waived.
     */
    @Test
    void certificateWithInconclusiveValidation_doesNotEarnTheWaiver() throws Exception {
        Certificate unvalidated = inventoryCertificate(RA_PROFILE_UUID);
        unvalidated.setValidationStatus(CertificateValidationStatus.FAILED);
        when(certificateService.getCertificateEntityByFingerprint(any())).thenReturn(unvalidated);

        assertFalse(service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    @Test
    void certificateWithPendingIssue_isRejected() throws Exception {
        Certificate pending = inventoryCertificate(RA_PROFILE_UUID);
        pending.setState(CertificateState.PENDING_ISSUE);
        when(certificateService.getCertificateEntityByFingerprint(any())).thenReturn(pending);

        assertThrows(ScepException.class, () -> service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    @Test
    void certificateWithPendingRevoke_isRejected() throws Exception {
        Certificate pending = inventoryCertificate(RA_PROFILE_UUID);
        pending.setState(CertificateState.PENDING_REVOKE);
        when(certificateService.getCertificateEntityByFingerprint(any())).thenReturn(pending);

        assertThrows(ScepException.class, () -> service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    @Test
    void certificateWithoutRaProfile_doesNotEarnTheWaiver() throws Exception {
        Certificate unassociated = inventoryCertificate(RA_PROFILE_UUID);
        unassociated.setRaProfileUuid(null);
        when(certificateService.getCertificateEntityByFingerprint(any())).thenReturn(unassociated);

        assertFalse(service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    /**
     * Pins the ordering the waiver rests on: possession of the key is proven before any state of the renewed
     * certificate is reported, so a client replaying a certificate it does not own learns nothing beyond the signature
     * failure.
     */
    @Test
    void archivedCertificateWithFailingSignature_reportsBadMessageCheck() throws Exception {
        Certificate archived = inventoryCertificate(RA_PROFILE_UUID);
        archived.setArchived(true);
        when(certificateService.getCertificateEntityByFingerprint(any())).thenReturn(archived);

        ScepException thrown = assertThrows(ScepException.class,
                () -> service.authenticateRenewal(renewalRequest(SUBJECT_DN, false)));
        assertEquals(FailInfo.BAD_MESSAGE_CHECK, thrown.getFailInfo());
    }

    /** The signature must be verified against the signer certificate's key, not some other key. */
    @Test
    void signatureIsVerifiedAgainstTheSignerCertificateKey() throws Exception {
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));
        ScepRequest request = renewalRequest(SUBJECT_DN, true);

        service.authenticateRenewal(request);

        ArgumentCaptor<PublicKey> verifiedKey = ArgumentCaptor.forClass(PublicKey.class);
        verify(request).verifySignature(verifiedKey.capture());
        assertEquals(clientCertificate.getPublicKey(), verifiedKey.getValue());
    }

    /**
     * A waived renewal must not be able to obtain names the renewed certificate does not already carry; asking for more
     * withholds the waiver, so the shared secret is required instead.
     */
    @Test
    void requestAskingForAdditionalSans_doesNotEarnTheWaiver() throws Exception {
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));

        assertFalse(service.authenticateRenewal(renewalRequestWithSans(dnsSan("extra.example.com"))));
    }

    @Test
    void requestAskingForHeldSans_isAnAuthenticatedRenewal() throws Exception {
        clientCertificate = selfSignedCertificate(clientKeyPair, SUBJECT_DN, dnsSan("held.example.com"));
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));

        assertTrue(service.authenticateRenewal(renewalRequestWithSans(dnsSan("held.example.com"))));
    }

    /**
     * An IP address SAN must compare equal across the two sides, or the waiver is silently withheld from network
     * devices renewing on an address they already hold — and a renewal carries no challenge password to fall back on.
     */
    @Test
    void requestAskingForHeldIpAddressSan_isAnAuthenticatedRenewal() throws Exception {
        clientCertificate = selfSignedCertificate(clientKeyPair, SUBJECT_DN, ipSan("192.168.0.1"));
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));

        assertTrue(service.authenticateRenewal(renewalRequestWithSans(ipSan("192.168.0.1"))));
    }

    @Test
    void requestAskingForAnUnheldIpAddressSan_doesNotEarnTheWaiver() throws Exception {
        clientCertificate = selfSignedCertificate(clientKeyPair, SUBJECT_DN, ipSan("192.168.0.1"));
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));

        assertFalse(service.authenticateRenewal(renewalRequestWithSans(ipSan("10.0.0.9"))));
    }

    /** An unverifiable signature is a rejection, not a crash, and reports the integrity failure. */
    @Test
    void signatureVerificationError_rejectedWithBadMessageCheck() throws Exception {
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));
        ScepRequest request = mock(ScepRequest.class);
        when(request.getSignerCertificate()).thenReturn(clientCertificate);
        when(request.verifySignature(any(PublicKey.class))).thenThrow(new CMSException("broken signature"));

        ScepException thrown = assertThrows(ScepException.class, () -> service.authenticateRenewal(request));
        assertEquals(FailInfo.BAD_MESSAGE_CHECK, thrown.getFailInfo());
    }

    /** Names that cannot be read withhold the waiver rather than being assumed harmless. */
    @Test
    void unreadableCertificationRequest_doesNotEarnTheWaiver() throws Exception {
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));
        JcaPKCS10CertificationRequest unreadable = mock(JcaPKCS10CertificationRequest.class);
        when(unreadable.getSubject()).thenReturn(new X500Name(SUBJECT_DN));
        when(unreadable.getEncoded()).thenThrow(new IOException("unreadable"));
        ScepRequest request = mock(ScepRequest.class);
        when(request.getSignerCertificate()).thenReturn(clientCertificate);
        when(request.getPkcs10Request()).thenReturn(unreadable);
        when(request.verifySignature(any(PublicKey.class))).thenReturn(true);

        assertFalse(service.authenticateRenewal(request));
    }

    @Test
    void archivedCertificate_isRejected() throws Exception {
        Certificate archived = inventoryCertificate(RA_PROFILE_UUID);
        archived.setArchived(true);
        when(certificateService.getCertificateEntityByFingerprint(any())).thenReturn(archived);

        assertThrows(ScepException.class, () -> service.authenticateRenewal(renewalRequest(SUBJECT_DN, true)));
    }

    @Test
    void subjectDnMismatch_isRejected() throws Exception {
        when(certificateService.getCertificateEntityByFingerprint(any()))
                .thenReturn(inventoryCertificate(RA_PROFILE_UUID));

        assertThrows(ScepException.class, () -> service.authenticateRenewal(renewalRequest("CN=somebody-else", true)));
    }

    private Certificate inventoryCertificate(UUID raProfileUuid) {
        Certificate certificate = new Certificate();
        certificate.setUuid(UUID.randomUUID());
        certificate.setSubjectDn(SUBJECT_DN);
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setRaProfileUuid(raProfileUuid);
        // 10 days left of a 40-day validity: inside the profile's 30-day renewal threshold.
        certificate.setNotBefore(new Date(System.currentTimeMillis() - 30L * 24 * 3600 * 1000));
        certificate.setNotAfter(new Date(System.currentTimeMillis() + 10L * 24 * 3600 * 1000));
        return certificate;
    }

    private ScepRequest renewalRequest(String csrSubjectDn, boolean signatureVerifies) throws Exception {
        ScepRequest request = mock(ScepRequest.class);
        when(request.getSignerCertificate()).thenReturn(clientCertificate);
        when(request.getPkcs10Request()).thenReturn(certificationRequest(csrSubjectDn, (GeneralNames) null));
        when(request.verifySignature(any(PublicKey.class))).thenReturn(signatureVerifies);
        return request;
    }

    private ScepRequest renewalRequestWithSans(GeneralNames sans) throws Exception {
        ScepRequest request = mock(ScepRequest.class);
        when(request.getSignerCertificate()).thenReturn(clientCertificate);
        when(request.getPkcs10Request()).thenReturn(certificationRequest(SUBJECT_DN, sans));
        when(request.verifySignature(any(PublicKey.class))).thenReturn(true);
        return request;
    }

    private JcaPKCS10CertificationRequest certificationRequest(String subjectDn, GeneralNames sans) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(clientKeyPair.getPrivate());
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                clientKeyPair.getPublic());
        if (sans != null) {
            ExtensionsGenerator extensions = new ExtensionsGenerator();
            extensions.addExtension(Extension.subjectAlternativeName, false, sans);
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        }
        return new JcaPKCS10CertificationRequest(builder.build(signer));
    }

    private static GeneralNames dnsSan(String dnsName) {
        return new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName));
    }

    private static GeneralNames ipSan(String ipAddress) {
        return new GeneralNames(new GeneralName(GeneralName.iPAddress, ipAddress));
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate selfSignedCertificate(KeyPair keyPair, String subjectDn) throws Exception {
        return selfSignedCertificate(keyPair, subjectDn, (GeneralNames) null);
    }

    private static X509Certificate selfSignedCertificate(KeyPair keyPair, String subjectDn, GeneralNames sans)
            throws Exception {
        X500Name dn = new X500Name(subjectDn);
        Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3_600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(dn,
                BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, dn, keyPair.getPublic());
        if (sans != null) {
            builder.addExtension(Extension.subjectAlternativeName, false, sans);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }
}
