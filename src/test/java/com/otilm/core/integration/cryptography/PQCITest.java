package com.otilm.core.integration.cryptography;

import com.otilm.core.util.KeySizeUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

@SpringBootTest
class PQCITest {

    public static final String FALCON = "Falcon";

    public static final String PURE_ML_DSA = "ML-DSA";
    public static final String HASH_ML_DSA = "HASH-ML-DSA";

    private static final String PURE_SLH_DSA = "SLH-DSA";
    private static final String HASH_SLH_DSA = "HASH-SLH-DSA";


    @BeforeEach
    void setUp() {
        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            provider = new BouncyCastleProvider();
            Security.addProvider(provider);
        }
    }

    @Test
    void testMLDSASignature() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        Assertions.assertTrue(signAndVerify(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44, PURE_ML_DSA));
        Assertions.assertTrue(signAndVerify(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44, HASH_ML_DSA));
        Assertions.assertTrue(signAndVerify(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44_with_sha512, HASH_ML_DSA));
        Assertions.assertThrows(Exception.class, () -> signAndVerify(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44_with_sha512, PURE_ML_DSA));
    }

    @Test
    void testSLHDSASignature() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        Assertions.assertTrue(signAndVerify(PURE_SLH_DSA, SLHDSAParameterSpec.slh_dsa_shake_128s, PURE_SLH_DSA));
        Assertions.assertTrue(signAndVerify(PURE_SLH_DSA, SLHDSAParameterSpec.slh_dsa_shake_128s, HASH_SLH_DSA));
        Assertions.assertTrue(signAndVerify(PURE_SLH_DSA, SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256, HASH_SLH_DSA));
        Assertions.assertTrue(signAndVerify(PURE_SLH_DSA, SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256, SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256.getName()));
        Assertions.assertThrows(Exception.class, () -> signAndVerify(PURE_SLH_DSA, SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256, PURE_SLH_DSA));
    }

    @Test
    void testFalconCsr() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, OperatorCreationException, PKCSException {
        PKCS10CertificationRequest csr = generateCsr(FALCON, FalconParameterSpec.falcon_512, FALCON + "-512", 7176);
        Assertions.assertEquals(FALCON.toUpperCase(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));

        csr = generateCsr(FALCON, FalconParameterSpec.falcon_1024, FALCON + "-1024", 14344);
        Assertions.assertEquals(FALCON.toUpperCase(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));
    }

    @Test
    void testMLDSACsr() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, OperatorCreationException, PKCSException {
        PKCS10CertificationRequest csr = generateCsr(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44, PURE_ML_DSA, 10496);
        Assertions.assertEquals(MLDSAParameterSpec.ml_dsa_44.getName(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));

        // When generating CSR with key that does not have hash in parameters, HASH-ML-DSA is overwritten to ML-DSA
        csr = generateCsr(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44, HASH_ML_DSA, 10496);
        Assertions.assertEquals(MLDSAParameterSpec.ml_dsa_44.getName(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));

        csr = generateCsr(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44_with_sha512, HASH_ML_DSA, 10496);
        Assertions.assertEquals(MLDSAParameterSpec.ml_dsa_44_with_sha512.getName(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));

        csr = generateCsr(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44_with_sha512, PURE_ML_DSA, 10496);
        Assertions.assertEquals(MLDSAParameterSpec.ml_dsa_44_with_sha512.getName(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));

        csr = generateCsr(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44_with_sha512, MLDSAParameterSpec.ml_dsa_44_with_sha512.getName(), 10496);
        Assertions.assertEquals(MLDSAParameterSpec.ml_dsa_44_with_sha512.getName(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));

        csr = generateCsr(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44_with_sha512, MLDSAParameterSpec.ml_dsa_44_with_sha512.getName(), 10496);
        Assertions.assertEquals(MLDSAParameterSpec.ml_dsa_44_with_sha512.getName(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));

        Assertions.assertThrows(OperatorCreationException.class, () -> generateCsr(PURE_ML_DSA, MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_44_with_sha512.getName(), 10496));
    }

    @Test
    void testSLHDSACsr() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, OperatorCreationException, PKCSException {
        PKCS10CertificationRequest csr = generateCsr(PURE_SLH_DSA, SLHDSAParameterSpec.slh_dsa_shake_128s, PURE_SLH_DSA, 256);
        Assertions.assertEquals(SLHDSAParameterSpec.slh_dsa_shake_128s.getName(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));

        // When generating CSR with key that does not have hash in parameters, HASH-ML-DSA is overwritten to ML-DSA
        csr = generateCsr(PURE_SLH_DSA, SLHDSAParameterSpec.slh_dsa_shake_128s, HASH_SLH_DSA, 256);
        Assertions.assertEquals(SLHDSAParameterSpec.slh_dsa_shake_128s.getName(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));

        csr = generateCsr(PURE_SLH_DSA, SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128, HASH_SLH_DSA, 256);
        Assertions.assertEquals(SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128.getName(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));

        csr = generateCsr(PURE_SLH_DSA, SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128, HASH_SLH_DSA, 256);
        Assertions.assertEquals(SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128.getName(), new DefaultAlgorithmNameFinder().getAlgorithmName(csr.getSignatureAlgorithm()));
        Assertions.assertTrue(verifyCsr(csr));
    }


    private static PKCS10CertificationRequest generateCsr(String keyAlgorithm, AlgorithmParameterSpec keyParameters, String signatureAlgorithm, int expectedKeySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, OperatorCreationException {
        KeyPair keyPair = getKeyPair(keyAlgorithm, keyParameters);
        Assertions.assertEquals(expectedKeySize, KeySizeUtil.getKeyLength(keyPair.getPublic()));

        X500Name name = new X500Name("CN=cn");
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(Objects.equals(keyAlgorithm, FALCON) ? BouncyCastlePQCProvider.PROVIDER_NAME : BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                name,
                keyPair.getPublic());
        return p10Builder.build(signer);
    }

    private static KeyPair getKeyPair(String keyAlgorithm, AlgorithmParameterSpec keyParameters) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(keyParameters);
        return keyPairGenerator.generateKeyPair();
    }

    private static boolean verifyCsr(PKCS10CertificationRequest csr) throws OperatorCreationException, PKCSException {
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo());
        return csr.isSignatureValid(verifierProvider);
    }

    private static boolean signAndVerify(String keyGenAlgorithm, AlgorithmParameterSpec keyGenParameter, String signatureAlgorithm) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        KeyPair keyPair = getKeyPair(keyGenAlgorithm, keyGenParameter);
        Signature signature = Signature.getInstance(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.update(keyPair.getPublic().getEncoded());
        byte[] signedDate = signature.sign();

        signature.initVerify(keyPair.getPublic());
        signature.update(keyPair.getPublic().getEncoded());
        return signature.verify(signedDate);
    }

}
