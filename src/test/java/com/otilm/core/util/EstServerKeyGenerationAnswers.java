package com.otilm.core.util;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

/**
 * Reads the {@code multipart/mixed} answer to {@code /serverkeygen}: the PKCS#8 key of its first part and the
 * certificate of the certs-only CMS of its second.
 */
public final class EstServerKeyGenerationAnswers {

    private static final String CRLF = "\r\n";
    private static final byte[] PROBE = {1, 2, 3};

    private EstServerKeyGenerationAnswers() {
    }

    /** @return the DER PKCS#8 key of the answer */
    public static byte[] keyOf(ResponseEntity<byte[]> response) {
        return Base64.getMimeDecoder().decode(partBodyOf(response, 1));
    }

    /** @return the only certificate of the answer */
    public static X509Certificate certificateOf(ResponseEntity<byte[]> response) throws Exception {
        CMSSignedData signedData = new CMSSignedData(Base64.getMimeDecoder().decode(partBodyOf(response, 2)));
        var held = signedData.getCertificates().getMatches(null);
        if (held.size() != 1) {
            throw new IllegalStateException("The answer holds " + held.size() + " certificates");
        }
        return new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) held.iterator().next());
    }

    /**
     * @param signatureAlgorithm the JCA name of a signature algorithm of the key, such as {@code SHA256withECDSA}
     * @return whether the key signs what the public key of the certificate verifies
     */
    public static boolean isKeyOf(byte[] pkcs8, X509Certificate certificate, String signatureAlgorithm)
            throws Exception {
        String keyAlgorithm = PrivateKeyInfo.getInstance(pkcs8).getPrivateKeyAlgorithm().getAlgorithm().getId();
        PrivateKey key = KeyFactory
                .getInstance(keyAlgorithm, BouncyCastleProvider.PROVIDER_NAME)
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        Signature signer = Signature.getInstance(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign(key);
        signer.update(PROBE);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        String certifiedAlgorithm = SubjectPublicKeyInfo
                .getInstance(certificate.getPublicKey().getEncoded())
                .getAlgorithm()
                .getAlgorithm()
                .getId();
        PublicKey certifiedKey = KeyFactory
                .getInstance(certifiedAlgorithm, BouncyCastleProvider.PROVIDER_NAME)
                .generatePublic(new X509EncodedKeySpec(certificate.getPublicKey().getEncoded()));
        verifier.initVerify(certifiedKey);
        verifier.update(PROBE);
        return verifier.verify(signature);
    }

    private static String partBodyOf(ResponseEntity<byte[]> response, int index) {
        String contentType = response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
        String boundary = contentType.substring(contentType.indexOf("boundary=") + "boundary=".length());
        String body = new String(response.getBody(), StandardCharsets.US_ASCII);
        String part = body.split(Pattern.quote("--" + boundary), -1)[index];
        return part.substring(part.indexOf(CRLF + CRLF) + 2 * CRLF.length()).trim();
    }
}
