package com.czertainly.core.util;

import com.czertainly.api.model.core.certificate.QcType;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CertificateTestUtil {

    public static X509Certificate createHybridCertificate() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, InvalidKeyException, SignatureException, OperatorCreationException, CertificateException {
        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            provider = new BouncyCastleProvider();
            Security.addProvider(provider);
        }

        KeyPairGenerator defaultKeyGen = KeyPairGenerator.getInstance("RSA");
        defaultKeyGen.initialize(2048);
        KeyPair defaultKeyPair = defaultKeyGen.generateKeyPair();
        Date notBefore = new Date();
        Date notAfter = new Date(Long.MAX_VALUE);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=issuer"), BigInteger.ONE, notBefore, notAfter, new X500Name("CN=subject"), defaultKeyPair.getPublic());

        KeyPairGenerator altKeyGen = KeyPairGenerator.getInstance("ML-DSA");
        altKeyGen.initialize(MLDSAParameterSpec.ml_dsa_44);
        KeyPair alternativeKeyPair = altKeyGen.generateKeyPair();

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        SubjectAltPublicKeyInfo subjectAltPublicKeyInfo = SubjectAltPublicKeyInfo.getInstance(
                ASN1Sequence.getInstance(alternativeKeyPair.getPublic().getEncoded()));
        certBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false, subjectAltPublicKeyInfo);
        extensionsGenerator.addExtension(Extension.subjectAltPublicKeyInfo, false, subjectAltPublicKeyInfo);

        AlgorithmIdentifier altSignatureAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44);
        AltSignatureAlgorithm altSignatureAlgorithm1 = new AltSignatureAlgorithm(altSignatureAlgorithm);
        certBuilder.addExtension(Extension.altSignatureAlgorithm, false, altSignatureAlgorithm1);
        extensionsGenerator.addExtension(Extension.altSignatureAlgorithm, false, altSignatureAlgorithm1);

        V3TBSCertificateGenerator tbsCertificateGenerator = new V3TBSCertificateGenerator();
        tbsCertificateGenerator.setIssuer(new X500Name("CN=issuer"));
        tbsCertificateGenerator.setSerialNumber(new ASN1Integer(BigInteger.ONE));
        tbsCertificateGenerator.setEndDate(new Time(notAfter));
        tbsCertificateGenerator.setStartDate(new Time(notBefore));
        tbsCertificateGenerator.setSubject(new X500Name("CN=subject"));
        tbsCertificateGenerator.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(defaultKeyPair.getPublic().getEncoded()));
        tbsCertificateGenerator.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption));
        tbsCertificateGenerator.setExtensions(extensionsGenerator.generate());
        TBSCertificate tbsCertificate = tbsCertificateGenerator.generateTBSCertificate();

        Signature signature = Signature.getInstance("ML-DSA");
        signature.initSign(alternativeKeyPair.getPrivate());
        signature.update(tbsCertificate.getEncoded());
        byte[] signedData = signature.sign();
        AltSignatureValue altSignatureValue = new AltSignatureValue(signedData);
        certBuilder.addExtension(Extension.altSignatureValue, false, altSignatureValue);

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(defaultKeyPair.getPrivate());
        return converter.getCertificate(certBuilder.build(signer));
    }

    public static X509Certificate createCertificateWithEku(boolean critical) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {
        ensureBouncyCastleProvider();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=test"), BigInteger.ONE, notBefore, notAfter, new X500Name("CN=test"), keyPair.getPublic());
        certBuilder.addExtension(Extension.extendedKeyUsage, critical,
                new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth}));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }

    public static X509Certificate createCACertificate() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {
        ensureBouncyCastleProvider();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=test-ca"), BigInteger.ONE, notBefore, notAfter, new X500Name("CN=test-ca"), keyPair.getPublic());
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }

    public static X509Certificate createCertificateWithoutEku() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        ensureBouncyCastleProvider();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=test"), BigInteger.ONE, notBefore, notAfter, new X500Name("CN=test"), keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }

    public static X509Certificate createTimestampingCertificate(boolean critical) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {
        ensureBouncyCastleProvider();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=test-tsa"), BigInteger.ONE, notBefore, notAfter, new X500Name("CN=test-tsa"), keyPair.getPublic());
        certBuilder.addExtension(Extension.extendedKeyUsage, critical,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }

    public static X509Certificate createTimestampingCertificateWithExtraEku() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {
        ensureBouncyCastleProvider();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=test-tsa-extra"), BigInteger.ONE, notBefore, notAfter, new X500Name("CN=test-tsa-extra"), keyPair.getPublic());
        certBuilder.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_timeStamping, KeyPurposeId.id_kp_serverAuth}));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }

    public static X509Certificate createQualifiedTimestampingCertificate() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {
        ensureBouncyCastleProvider();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=test-qtsa"), BigInteger.ONE, notBefore, notAfter, new X500Name("CN=test-qtsa"), keyPair.getPublic());
        certBuilder.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        ASN1EncodableVector stmts = new ASN1EncodableVector();
        stmts.add(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance));
        certBuilder.addExtension(Extension.qCStatements, false, new DERSequence(stmts));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }

    public static X509Certificate createTimestampingCertificate() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {
        ensureBouncyCastleProvider();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return createTimestampingCertificate(keyGen.generateKeyPair());
    }

    /**
     * Creates an end-entity certificate whose issuer is a freshly-generated CA key that is <em>not</em> stored in any
     * certificate inventory. Because the certificate is signed by a key other than its own, {@code isSelfSigned}
     * returns {@code false}, and because the issuing CA is absent from the inventory, {@code getCertificateChain} will
     * report an incomplete chain.
     */
    public static X509Certificate createEndEntityCertificate() throws CertificateException, NoSuchAlgorithmException, OperatorCreationException {
        ensureBouncyCastleProvider();
        KeyPairGenerator caKeyGen = KeyPairGenerator.getInstance("RSA");
        caKeyGen.initialize(2048);
        KeyPair caKeyPair = caKeyGen.generateKeyPair();

        KeyPairGenerator eeKeyGen = KeyPairGenerator.getInstance("RSA");
        eeKeyGen.initialize(2048);
        KeyPair eeKeyPair = eeKeyGen.generateKeyPair();

        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=external-ca"), BigInteger.TWO, notBefore, notAfter,
                new X500Name("CN=test-ee"), eeKeyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caKeyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }

    public static X509Certificate createTimestampingCertificate(KeyPair keyPair) throws OperatorCreationException, CertificateException, IOException {
        return createTimestampingCertificate(keyPair, "SHA256withRSA");
    }

    /**
     * Creates a self-signed TSA certificate with critical id-kp-timeStamping EKU,
     * signed using the supplied JCA {@code signatureAlgorithm}
     * (e.g. {@code "SHA256withRSA"} or {@code "SHA256withECDSA"}).
     */
    public static X509Certificate createTimestampingCertificate(KeyPair keyPair, String signatureAlgorithm) throws OperatorCreationException, CertificateException, IOException {
        ensureBouncyCastleProvider();
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=test-tsa"), BigInteger.ONE, notBefore, notAfter, new X500Name("CN=test-tsa"), keyPair.getPublic());
        certBuilder.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }

    private static void ensureBouncyCastleProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Builds a self-signed RSA certificate that carries a QCStatements extension (OID 1.3.6.1.5.5.7.1.3)
     * populated with the requested ETSI EN 319 412-5 statements.
     *
     * @param qcCompliance    include id-etsi-qcs-QcCompliance (0.4.0.1862.1.1)
     * @param qcSscd          include id-etsi-qcs-QcSSCD (0.4.0.1862.1.4)
     * @param qcTypes         QcType OIDs to include (may be null/empty)
     * @param ccLegislation   ISO 3166-1 alpha-2 country codes for QcCClegislation (may be null/empty)
     */
    public static X509Certificate createCertificateWithQcStatements(
            boolean qcCompliance, boolean qcSscd, List<QcType> qcTypes, List<String> ccLegislation)
            throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {
        ensureBouncyCastleProvider();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=qc-test"), BigInteger.TWO, notBefore, notAfter,
                new X500Name("CN=qc-test"), keyPair.getPublic());

        // OIDs that match what CertificateUtil.parseQcStatements() recognises
        ASN1ObjectIdentifier QCT_ESIGN = new ASN1ObjectIdentifier("0.4.0.1862.1.6.1").intern();
        ASN1ObjectIdentifier QCT_ESEAL = new ASN1ObjectIdentifier("0.4.0.1862.1.6.2").intern();
        ASN1ObjectIdentifier QCT_WEB   = new ASN1ObjectIdentifier("0.4.0.1862.1.6.3").intern();
        ASN1ObjectIdentifier QC_CC_LEGISLATION = new ASN1ObjectIdentifier("0.4.0.1862.1.7").intern();

        List<QCStatement> statements = new ArrayList<>();
        if (qcCompliance) {
            statements.add(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance));
        }
        if (qcSscd) {
            statements.add(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD));
        }
        if (qcTypes != null && !qcTypes.isEmpty()) {
            ASN1EncodableVector typeVec = new ASN1EncodableVector();
            for (QcType t : qcTypes) {
                typeVec.add(switch (t) {
                    case ESIGN -> QCT_ESIGN;
                    case ESEAL -> QCT_ESEAL;
                    case WEB   -> QCT_WEB;
                });
            }
            statements.add(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType, new DERSequence(typeVec)));
        }
        if (ccLegislation != null && !ccLegislation.isEmpty()) {
            ASN1EncodableVector ccVec = new ASN1EncodableVector();
            for (String cc : ccLegislation) {
                ccVec.add(new DERPrintableString(cc));
            }
            statements.add(new QCStatement(QC_CC_LEGISLATION, new DERSequence(ccVec)));
        }

        ASN1EncodableVector stmtVec = new ASN1EncodableVector();
        for (QCStatement stmt : statements) {
            stmtVec.add(stmt);
        }
        certBuilder.addExtension(Extension.qCStatements, false, new DERSequence(stmtVec));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }
}
