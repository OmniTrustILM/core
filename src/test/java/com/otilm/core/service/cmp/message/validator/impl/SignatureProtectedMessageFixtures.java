package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.core.service.cmp.CmpTestUtil;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Signature-protected CMP messages whose first extra certificate holds a public key exactly as it is encoded, so that
 * no key is built for the certificate when the message is made.
 */
public final class SignatureProtectedMessageFixtures {

    private static final String SUBJECT = "CN=cmp-client";
    private static final String TRANSACTION_ID = "protection-transaction";

    private SignatureProtectedMessageFixtures() {
    }

    /**
     * An ir signed with the EC key pair, whose first extra certificate holds the public key and is signed with the same
     * key pair.
     */
    public static PKIMessage signatureProtectedMessage(KeyPair ecSigningKeyPair, SubjectPublicKeyInfo certificateKey)
            throws Exception {
        X500Name name = new X500Name(SUBJECT);
        Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3_600_000L);
        X509CertificateHolder certificate = new X509v3CertificateBuilder(name, BigInteger.ONE, notBefore, notAfter,
                name, certificateKey).build(signerOf(ecSigningKeyPair));
        return CmpTestUtil
                .createPkiMessageBuilder(TRANSACTION_ID, CmpTestUtil.createCrmfBody(ecSigningKeyPair, 0))
                .addCMPCertificate(certificate)
                .build(signerOf(ecSigningKeyPair))
                .toASN1Structure();
    }

    /** The public key of the EC key pair with the parameters of its named curve written out, as the key states them. */
    public static SubjectPublicKeyInfo onExplicitCurve(KeyPair ecKeyPair, String curveName) {
        SubjectPublicKeyInfo onNamedCurve = SubjectPublicKeyInfo.getInstance(ecKeyPair.getPublic().getEncoded());
        AlgorithmIdentifier explicitCurve = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                new X962Parameters(ECNamedCurveTable.getByName(curveName)));
        return new SubjectPublicKeyInfo(explicitCurve, onNamedCurve.getPublicKeyData().getBytes());
    }

    private static ContentSigner signerOf(KeyPair keyPair) throws Exception {
        return new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
    }
}
