package com.otilm.core.service.writer;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateKeyWriterTest {

    private static final int UNSIZED = -1;

    @Mock
    private CryptographicKeyRepository keyRepository;
    @Mock
    private CryptographicKeyItemRepository itemRepository;
    @InjectMocks
    private CertificateKeyWriter writer;

    @Test
    void describesTheKeyByItsParameterSet_whenTheCertificateKeyIsMlKem() throws Exception {
        // given
        when(itemRepository.insertWithFingerprintConflictResolve(any())).thenReturn(1);
        var mlKem768 = mlKemPublicKey();

        // when
        writer.uploadCertificatePublicKey("ml-kem", mlKem768, UNSIZED, "fingerprint");

        // then
        CryptographicKeyItem inserted = insertedItem();
        assertThat(inserted.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.MLKEM);
        assertThat(inserted.getParameterSet()).isEqualTo("ML-KEM-768");
        assertThat(inserted.getLength()).isEqualTo(9472);
    }

    @Test
    void classifiesTheKeyAsRsa_whenTheCertificateKeyIsRsaPss() throws Exception {
        // given
        when(itemRepository.insertWithFingerprintConflictResolve(any())).thenReturn(1);
        var rsaPss = rsaPssPublicKey();

        // when
        writer.uploadCertificatePublicKey("rsa-pss", rsaPss, 2048, "fingerprint");

        // then
        CryptographicKeyItem inserted = insertedItem();
        assertThat(inserted.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA);
        assertThat(inserted.getLength()).isEqualTo(2048);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CryptographicKeyItem insertedItem() {
        var inserted = ArgumentCaptor.forClass(CryptographicKeyItem.class);
        verify(itemRepository).insertWithFingerprintConflictResolve(inserted.capture());
        return inserted.getValue();
    }

    private static PublicKey mlKemPublicKey() throws Exception {
        var generator = KeyPairGenerator.getInstance("ML-KEM", new BouncyCastleProvider());
        generator.initialize(MLKEMParameterSpec.ml_kem_768);
        return generator.generateKeyPair().getPublic();
    }

    private static PublicKey rsaPssPublicKey() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSASSA-PSS", new BouncyCastleProvider());
        generator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        return generator.generateKeyPair().getPublic();
    }
}
