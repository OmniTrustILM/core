package com.otilm.core.service.handler;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.CryptographicKeyInternalService;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateHandlerDiscoveredKeyUploadTest {

    @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private CryptographicKeyInternalService cryptographicKeyService;

    private CertificateHandler handler;
    private PublicKey publicKey;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        handler = new CertificateHandler();
        handler.setCertificateRepository(certificateRepository);
        handler.setCryptographicKeyInternalService(cryptographicKeyService);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        publicKey = generator.generateKeyPair().getPublic();
    }

    @Test
    void uploadDiscoveredCertificateKey_whenNoCommittedCertificate_skipsAndReportsNotAssociated()
            throws NoSuchAlgorithmException {
        List<UUID> uuids = List.of(UUID.randomUUID());
        when(certificateRepository.findFirstByUuidIn(uuids)).thenReturn(null);

        boolean associated = handler.uploadDiscoveredCertificateKey(publicKey, uuids);

        assertThat(associated).isFalse();
        verify(cryptographicKeyService, never()).uploadCertificatePublicKey(anyString(), any(), anyInt(), anyString());
        verify(certificateRepository, never()).setKeyUuid(any(), anyList());
    }

    @Test
    void uploadDiscoveredCertificateAltKey_whenNoCommittedCertificate_skipsAndReportsNotAssociated()
            throws NoSuchAlgorithmException {
        List<UUID> uuids = List.of(UUID.randomUUID());
        when(certificateRepository.findFirstByUuidIn(uuids)).thenReturn(null);

        boolean associated = handler.uploadDiscoveredCertificateAltKey(publicKey, uuids);

        assertThat(associated).isFalse();
        verify(cryptographicKeyService, never()).uploadCertificatePublicKey(anyString(), any(), anyInt(), anyString());
        verify(certificateRepository, never()).setAltKeyUuidAndHybridCertificate(any(), anyList());
    }

    @Test
    void uploadDiscoveredCertificateKey_whenNoCommittedCertificate_skipsBeforeConsultingExistingKey()
            throws NoSuchAlgorithmException {
        List<UUID> uuids = List.of(UUID.randomUUID());
        when(certificateRepository.findFirstByUuidIn(uuids)).thenReturn(null);

        boolean associated = handler.uploadDiscoveredCertificateKey(publicKey, uuids);

        // The committed-certificate check must short-circuit before the existing-key lookup, so a pre-existing
        // shared key cannot make a skipped association look clean.
        assertThat(associated).isFalse();
        verify(cryptographicKeyService, never()).findKeyByFingerprint(anyString());
        verify(cryptographicKeyService, never()).uploadCertificatePublicKey(anyString(), any(), anyInt(), anyString());
        verify(certificateRepository, never()).setKeyUuid(any(), anyList());
    }

    @Test
    void uploadDiscoveredCertificateKey_whenCertificateCommitted_uploadsKeyAssociatesAndReportsAssociated()
            throws NoSuchAlgorithmException {
        List<UUID> uuids = List.of(UUID.randomUUID());
        UUID keyUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setCommonName("example.com");

        when(certificateRepository.findFirstByUuidIn(uuids)).thenReturn(certificate);
        when(cryptographicKeyService.findKeyByFingerprint(anyString())).thenReturn(null);
        when(cryptographicKeyService
                .uploadCertificatePublicKey(eq("certKey_example.com"), any(), anyInt(), anyString()))
                .thenReturn(keyUuid);

        boolean associated = handler.uploadDiscoveredCertificateKey(publicKey, uuids);

        assertThat(associated).isTrue();
        verify(certificateRepository).setKeyUuid(keyUuid, uuids);
    }

    @Test
    void uploadDiscoveredCertificateAltKey_whenCertificateCommitted_uploadsKeyAssociatesAndReportsAssociated()
            throws NoSuchAlgorithmException {
        List<UUID> uuids = List.of(UUID.randomUUID());
        UUID keyUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setCommonName("example.com");

        when(certificateRepository.findFirstByUuidIn(uuids)).thenReturn(certificate);
        when(cryptographicKeyService.findKeyByFingerprint(anyString())).thenReturn(null);
        when(cryptographicKeyService
                .uploadCertificatePublicKey(eq("altCertKey_example.com"), any(), anyInt(), anyString()))
                .thenReturn(keyUuid);

        boolean associated = handler.uploadDiscoveredCertificateAltKey(publicKey, uuids);

        assertThat(associated).isTrue();
        verify(certificateRepository).setAltKeyUuidAndHybridCertificate(keyUuid, uuids);
    }

    @Test
    void uploadDiscoveredCertificateKey_whenKeyAlreadyExistsAndCertificateCommitted_skipsUploadButAssociatesAndReportsAssociated()
            throws NoSuchAlgorithmException {
        List<UUID> uuids = List.of(UUID.randomUUID());
        UUID keyUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setCommonName("example.com");

        when(certificateRepository.findFirstByUuidIn(uuids)).thenReturn(certificate);
        when(cryptographicKeyService.findKeyByFingerprint(anyString())).thenReturn(keyUuid);

        boolean associated = handler.uploadDiscoveredCertificateKey(publicKey, uuids);

        assertThat(associated).isTrue();
        verify(cryptographicKeyService, never()).uploadCertificatePublicKey(anyString(), any(), anyInt(), anyString());
        verify(certificateRepository).setKeyUuid(keyUuid, uuids);
    }

    @Test
    void uploadDiscoveredCertificateKey_whenCommonNameNull_namesKeyBySerialNumber() throws NoSuchAlgorithmException {
        List<UUID> uuids = List.of(UUID.randomUUID());
        UUID keyUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setCommonName(null);
        certificate.setSerialNumber("AB12CD");

        when(certificateRepository.findFirstByUuidIn(uuids)).thenReturn(certificate);
        when(cryptographicKeyService.findKeyByFingerprint(anyString())).thenReturn(null);
        when(cryptographicKeyService.uploadCertificatePublicKey(eq("certKey_AB12CD"), any(), anyInt(), anyString()))
                .thenReturn(keyUuid);

        boolean associated = handler.uploadDiscoveredCertificateKey(publicKey, uuids);

        assertThat(associated).isTrue();
        verify(certificateRepository).setKeyUuid(keyUuid, uuids);
    }
}
