package com.otilm.core.service.cmp.mock;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

public class CertTestUtil {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(CertTestUtil.class.getName());

    private static final JcaPEMKeyConverter JCA_KEY_CONVERTER = new JcaPEMKeyConverter();
    private static PrivateKey SIGNING_CERT_PRIV_KEY;

    public static X509Certificate createCertificateV3(
            X500Name subject,
            SubjectPublicKeyInfo publicKey,
            X509Certificate issuingCert,
            Extensions extensionsFromTemplate)
            throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException, PEMException {
        return new CertificationGeneratorStrategy().generateCertificate(
                subject, publicKey, issuingCert,
                getPrivateKeyForSigning(),
                extensionsFromTemplate);
    }

    private static class CertificationGeneratorStrategy {
        public X509Certificate generateCertificateCA(KeyPair issuerKeyPair, KeyPair subjectKeyPair, X500Name issuer, X500Name subject)
                throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException, PEMException {
            SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(subjectKeyPair.getPublic().getEncoded());

            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    /* issuer       */issuer,
                    /* serialNumber */new BigInteger(10, new SecureRandom()),
                    /* start        */new Date(),
                    /* until        */Date.from(LocalDate.now().plus(365*10, ChronoUnit.DAYS)
                    .atStartOfDay().toInstant(ZoneOffset.UTC)),
                    /* subject      */subject,
                    /* publicKey    */pubKeyInfo
            );
            // Basic Constraints
            PublicKey pubKey = JCA_KEY_CONVERTER.getPublicKey(pubKeyInfo);
            final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            //*
            certificateBuilder.addExtension(
                    new ASN1ObjectIdentifier("2.5.29.15"),
                    false,
                    new X509KeyUsage(
                            X509KeyUsage.digitalSignature |
                                    X509KeyUsage.nonRepudiation   |
                                    X509KeyUsage.keyEncipherment  |
                                    X509KeyUsage.cRLSign |
                                    X509KeyUsage.dataEncipherment));
            //*/
            certificateBuilder.addExtension(
                    Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
            certificateBuilder.addExtension(
                    Extension.basicConstraints, true, new BasicConstraints(true));//true is for CA
            // -------------------------------------

            // -- bouncy castle - certification singer
            PrivateKey issuerPrivateKey = issuerKeyPair.getPrivate();
            ContentSigner contentSigner = new JcaContentSignerBuilder(
                    getSigningAlgNameFromKeyAlg(issuerPrivateKey.getAlgorithm())) // /*"SHA256WithRSA"*/
                    .build(issuerPrivateKey);

            // -- create x.509 certificate
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME/*new BouncyCastleProvider()*/)
                    .getCertificate(certificateBuilder.build(contentSigner));
        }

        /**
         * @see 3gpp mobile spec: 6.1.2	Interconnection CA Certificate profile
         */
        public X509Certificate generateCertificate(X500Name subject, SubjectPublicKeyInfo publicKey,
                                                   X509Certificate issuer, PrivateKey issuerPrivateKey,
                                                   Extensions extensionsFromTemplate)
                throws CertificateException, OperatorCreationException, CertIOException, PEMException, NoSuchAlgorithmException {
            PublicKey pubKey = JCA_KEY_CONVERTER.getPublicKey(publicKey);
            // -- bouncy castle - certification builder
            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    /* issuer       */issuer.getSubjectX500Principal(),
                    /* serialNumber */new BigInteger(10, new SecureRandom()),
                    /* start        */new Date(),
                    /* until        */Date.from(LocalDate.now().plus(365, ChronoUnit.DAYS)
                    .atStartOfDay().toInstant(ZoneOffset.UTC)),
                    /* subject      */new X500Principal(subject.toString()),
                    /* publicKey    */pubKey
            );
            final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            if (extensionsFromTemplate != null) {
                Arrays.stream(extensionsFromTemplate.getExtensionOIDs()).forEach(oid -> {
                    try {
                        certificateBuilder.addExtension(extensionsFromTemplate.getExtension(oid));
                    } catch (final CertIOException e) {
                        LOG.warn("Problem with add oid extension", e);
                    }
                });
            }
            //*
            certificateBuilder.addExtension(
                    new ASN1ObjectIdentifier("2.5.29.15"),
                    false,
                    new X509KeyUsage(
                            X509KeyUsage.digitalSignature |
                                    X509KeyUsage.nonRepudiation   |
                                    X509KeyUsage.keyEncipherment  |
                                    X509KeyUsage.cRLSign |
                                    X509KeyUsage.dataEncipherment));
            //*/
            certificateBuilder.addExtension(
                    Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
            certificateBuilder.addExtension(
                    Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuer));
            certificateBuilder.addExtension(
                    Extension.basicConstraints, true, new BasicConstraints(false));// <-- BasicConstraints: true for CA, false for EndEntity
            // -------------------------------------

            // -- bouncy castle - certification singer
            ContentSigner contentSigner = new JcaContentSignerBuilder(
                    getSigningAlgNameFromKeyAlg(issuerPrivateKey.getAlgorithm())) // /*"SHA256WithRSA"*/
                    .build(issuerPrivateKey);

            // -- create x.509 certificate
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME/*new BouncyCastleProvider()*/)
                    .getCertificate(certificateBuilder.build(contentSigner));
        }

        public static Certificate selfSign(KeyPair keyPair, String subjectDN) throws OperatorCreationException, CertificateException, CertIOException {
            long now = System.currentTimeMillis();
            Date startDate = new Date(now);

            X500Name dnName = new X500Name(subjectDN);
            BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

            Calendar calendar = Calendar.getInstance();
            calendar.setTime(startDate);
            calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity

            Date endDate = calendar.getTime();
            String signatureAlgorithm = "SHA256WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                    .build(keyPair.getPrivate());
            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

            // Extensions --------------------------
            // Basic Constraints
            BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity
            certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.
            // -------------------------------------

            return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certBuilder.build(contentSigner));
        }
    }

    public static PrivateKey getPrivateKeyForSigning() { return SIGNING_CERT_PRIV_KEY; }

    public static String getSigningAlgNameFromKeyAlg(final String keyAlgorithm) {
        if (keyAlgorithm.startsWith("Ed")) {// EdDSA key
            return keyAlgorithm;
        }
        if ("EC".equals(keyAlgorithm) || "ECDSA".equals(keyAlgorithm)) {// EC key
            return "SHA384withECDSA";
        }
        return "SHA384with" + keyAlgorithm;
    }
}
