package com.otilm.core.service.cmp.registration;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.registration.RegistrationChallengeGate;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class CmpRegistrationResolverTest {

    private static final UUID CERT_UUID = UUID.randomUUID();
    private static final UUID RA_PROFILE_UUID = UUID.randomUUID();
    private static final String CHALLENGE = "the-challenge";
    private static final ASN1OctetString TID = new DEROctetString(new byte[]{1, 2, 3, 4});

    private CmpRegistrationResolver resolver;
    private CertificateRepository certificateRepository;
    private RegistrationChallengeGate gate;
    private RaProfile raProfile;

    @BeforeEach
    void setUp() {
        certificateRepository = mock(CertificateRepository.class);
        gate = mock(RegistrationChallengeGate.class);
        resolver = new CmpRegistrationResolver();
        resolver.setCertificateRepository(certificateRepository);
        resolver.setRegistrationChallengeGate(gate);
        raProfile = new RaProfile();
        raProfile.setUuid(RA_PROFILE_UUID);
    }

    private ASN1OctetString senderKid(String value) {
        return new DEROctetString(value.getBytes(StandardCharsets.UTF_8));
    }

    private Certificate registeredCertificate() {
        Certificate certificate = new Certificate();
        certificate.setUuid(CERT_UUID);
        certificate.setState(CertificateState.REGISTERED);
        certificate.setRaProfileUuid(RA_PROFILE_UUID);
        return certificate;
    }

    /** Makes the gate invoke the predicate with the stored plaintext and return its result. */
    private Answer<Boolean> gateRunsPredicateWith(String plaintext) {
        return invocation -> {
            Predicate<String> predicate = invocation.getArgument(2);
            return predicate.test(plaintext);
        };
    }

    @Test
    void matchedRequestReturnsCertificateAndCapturedChallenge() {
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(registeredCertificate()));
        when(gate.verify(eq(CERT_UUID), eq(CertificateEvent.ISSUE), any())).thenAnswer(gateRunsPredicateWith(CHALLENGE));

        CmpRegistrationResolver.RegistrationMacResolution resolution = Assertions.assertDoesNotThrow(() ->
                resolver.resolveAndVerify(raProfile, senderKid(CERT_UUID.toString()), CertificateEvent.ISSUE,
                        password -> new String(password, StandardCharsets.UTF_8).equals(CHALLENGE), TID));

        Assertions.assertEquals(CERT_UUID, resolution.certificate().getUuid());
        Assertions.assertEquals(CHALLENGE, resolution.challenge());
    }

    @Test
    void wrongMacRejectsGenericallyWithoutMatch() {
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(registeredCertificate()));
        when(gate.verify(eq(CERT_UUID), eq(CertificateEvent.ISSUE), any())).thenAnswer(gateRunsPredicateWith(CHALLENGE));

        ASN1OctetString senderKid = senderKid(CERT_UUID.toString());
        CmpProcessingException ex = Assertions.assertThrows(CmpProcessingException.class, () ->
                resolver.resolveAndVerify(raProfile, senderKid, CertificateEvent.ISSUE,
                        password -> false, TID));

        Assertions.assertTrue(ex.getMessage().contains(CmpRegistrationResolver.REGISTRATION_REJECTION), ex.getMessage());
    }

    @Test
    void gateDenialRejectsGenerically() {
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(registeredCertificate()));
        when(gate.verify(eq(CERT_UUID), eq(CertificateEvent.ISSUE), any()))
                .thenThrow(new ValidationException("locked"));

        ASN1OctetString senderKid = senderKid(CERT_UUID.toString());
        CmpProcessingException ex = Assertions.assertThrows(CmpProcessingException.class, () ->
                resolver.resolveAndVerify(raProfile, senderKid, CertificateEvent.ISSUE, password -> true, TID));

        Assertions.assertTrue(ex.getMessage().contains(CmpRegistrationResolver.REGISTRATION_REJECTION), ex.getMessage());
    }

    @Test
    void gateFalseRejectsGenerically() {
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(registeredCertificate()));
        when(gate.verify(eq(CERT_UUID), eq(CertificateEvent.ISSUE), any())).thenReturn(false);

        ASN1OctetString senderKid = senderKid(CERT_UUID.toString());
        CmpProcessingException ex = Assertions.assertThrows(CmpProcessingException.class, () ->
                resolver.resolveAndVerify(raProfile, senderKid, CertificateEvent.ISSUE, password -> true, TID));

        Assertions.assertTrue(ex.getMessage().contains(CmpRegistrationResolver.REGISTRATION_REJECTION), ex.getMessage());
    }

    @Test
    void unparseableSenderKidRejectsBeforeAnyGateCall() {
        ASN1OctetString senderKid = senderKid("not-a-uuid");
        Assertions.assertThrows(CmpProcessingException.class, () ->
                resolver.resolveAndVerify(raProfile, senderKid, CertificateEvent.ISSUE, password -> true, TID));

        verifyNoInteractions(gate);
    }

    @Test
    void wrongRaProfileRejectsBeforeAnyGateCall() {
        Certificate otherProfileCertificate = registeredCertificate();
        otherProfileCertificate.setRaProfileUuid(UUID.randomUUID());
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(otherProfileCertificate));

        ASN1OctetString senderKid = senderKid(CERT_UUID.toString());
        Assertions.assertThrows(CmpProcessingException.class, () ->
                resolver.resolveAndVerify(raProfile, senderKid, CertificateEvent.ISSUE, password -> true, TID));

        verifyNoInteractions(gate);
    }

    @Test
    void nonRegisteredStateRejectsIssueBeforeAnyGateCall() {
        Certificate issued = registeredCertificate();
        issued.setState(CertificateState.ISSUED);
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(issued));

        ASN1OctetString senderKid = senderKid(CERT_UUID.toString());
        Assertions.assertThrows(CmpProcessingException.class, () ->
                resolver.resolveAndVerify(raProfile, senderKid, CertificateEvent.ISSUE, password -> true, TID));

        verifyNoInteractions(gate);
    }

    @Test
    void rekeyAcceptsIssuedCertificate() {
        Certificate issued = registeredCertificate();
        issued.setState(CertificateState.ISSUED);
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(issued));
        when(gate.verify(eq(CERT_UUID), eq(CertificateEvent.REKEY), any())).thenAnswer(gateRunsPredicateWith(CHALLENGE));

        CmpRegistrationResolver.RegistrationMacResolution resolution = Assertions.assertDoesNotThrow(() ->
                resolver.resolveAndVerify(raProfile, senderKid(CERT_UUID.toString()), CertificateEvent.REKEY,
                        password -> new String(password, StandardCharsets.UTF_8).equals(CHALLENGE), TID));

        Assertions.assertEquals(CERT_UUID, resolution.certificate().getUuid());
    }

    @Test
    void rekeyRejectsRegisteredPlaceholderBeforeAnyGateCall() {
        // A REGISTERED placeholder has no key to rekey.
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(registeredCertificate()));

        ASN1OctetString senderKid = senderKid(CERT_UUID.toString());
        Assertions.assertThrows(CmpProcessingException.class, () ->
                resolver.resolveAndVerify(raProfile, senderKid, CertificateEvent.REKEY, password -> true, TID));

        verifyNoInteractions(gate);
    }

    @Test
    void followupAcceptsIssuedCertificateRegardlessOfState() {
        // pollReq/certConf arrive after the placeholder has issued; the state is not constrained, only that the
        // surviving authorization still verifies the MAC.
        Certificate issued = registeredCertificate();
        issued.setState(CertificateState.ISSUED);
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(issued));
        when(gate.verify(eq(CERT_UUID), eq(CertificateEvent.ISSUE), any())).thenAnswer(gateRunsPredicateWith(CHALLENGE));

        CmpRegistrationResolver.RegistrationMacResolution resolution = Assertions.assertDoesNotThrow(() ->
                resolver.resolveAndVerifyFollowup(raProfile, senderKid(CERT_UUID.toString()),
                        password -> new String(password, StandardCharsets.UTF_8).equals(CHALLENGE), TID));

        Assertions.assertEquals(CERT_UUID, resolution.certificate().getUuid());
        Assertions.assertEquals(CHALLENGE, resolution.challenge());
    }

    @Test
    void followupWrongMacRejectsGenerically() {
        Certificate issued = registeredCertificate();
        issued.setState(CertificateState.ISSUED);
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(issued));
        when(gate.verify(eq(CERT_UUID), eq(CertificateEvent.ISSUE), any())).thenAnswer(gateRunsPredicateWith(CHALLENGE));

        ASN1OctetString senderKid = senderKid(CERT_UUID.toString());
        CmpProcessingException ex = Assertions.assertThrows(CmpProcessingException.class, () ->
                resolver.resolveAndVerifyFollowup(raProfile, senderKid, password -> false, TID));

        Assertions.assertTrue(ex.getMessage().contains(CmpRegistrationResolver.REGISTRATION_REJECTION), ex.getMessage());
    }

    @Test
    void followupWrongRaProfileRejectsBeforeAnyGateCall() {
        Certificate other = registeredCertificate();
        other.setState(CertificateState.ISSUED);
        other.setRaProfileUuid(UUID.randomUUID());
        when(certificateRepository.findByUuid(CERT_UUID)).thenReturn(Optional.of(other));

        ASN1OctetString senderKid = senderKid(CERT_UUID.toString());
        Assertions.assertThrows(CmpProcessingException.class, () ->
                resolver.resolveAndVerifyFollowup(raProfile, senderKid, password -> true, TID));

        verifyNoInteractions(gate);
    }
}
