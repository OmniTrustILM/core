package com.otilm.core.util;

import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@SuppressWarnings("java:S2696")
public class OcspUtil {
    private static final Logger logger = LoggerFactory.getLogger(OcspUtil.class);

    /** How far the validity period of an OCSP answer may be off from this server's clock. */
    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);

    /** Position of digitalSignature in {@link X509Certificate#getKeyUsage()}. */
    private static final int DIGITAL_SIGNATURE = 0;

    private static int ocspReadTimeout; // milliseconds
    private static int ocspConnectTimeout; // milliseconds

    private static final Map<Integer, String> ocspResponseStatuses = Map
            .of(OCSPResponseStatus.SUCCESSFUL, "Successful", OCSPResponseStatus.MALFORMED_REQUEST, "Malformed request",
                    OCSPResponseStatus.INTERNAL_ERROR, "Internal error", OCSPResponseStatus.TRY_LATER, "Try later",
                    OCSPResponseStatus.SIG_REQUIRED, "Signature required", OCSPResponseStatus.UNAUTHORIZED,
                    "Unauthorized");

    @Value("${validation.ocsp.read-timeout:1000}")
    public void setOcspReadTimeout(int timeout) {
        ocspReadTimeout = timeout;
    }

    @Value("${validation.ocsp.connect-timeout:1000}")
    public void setOcspConnectTimeout(int timeout) {
        ocspConnectTimeout = timeout;
    }

    private OcspUtil() {

    }

    public static String getChainFromAia(X509Certificate certificate) throws IOException {
        byte[] octetBytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (octetBytes == null) {
            return null;
        }

        AuthorityInformationAccess aia = AuthorityInformationAccess
                .getInstance(JcaX509ExtensionUtils.parseExtensionValue(octetBytes));
        AccessDescription[] descriptions = aia.getAccessDescriptions();
        for (AccessDescription ad : descriptions) {
            if (ad.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
                GeneralName location = ad.getAccessLocation();
                if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    logger.debug("Chain for the certificate is {}", location.getName());
                    return location.getName().toString();
                }
            }
        }
        return null;
    }

    public static List<String> getOcspUrlFromCertificate(X509Certificate certificate) throws IOException {
        List<String> ocspUrls = new ArrayList<>();
        byte[] octetBytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (octetBytes == null) {
            return ocspUrls;
        }

        ASN1Primitive fromExtensionValue = JcaX509ExtensionUtils.parseExtensionValue(octetBytes);
        if (!(fromExtensionValue instanceof DLSequence)) {
            return ocspUrls;
        }

        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess
                .getInstance(fromExtensionValue);
        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {
            boolean correctAccessMethod = accessDescription
                    .getAccessMethod()
                    .equals(X509ObjectIdentifiers.ocspAccessMethod);
            if (!correctAccessMethod) {
                continue;
            }
            GeneralName name = accessDescription.getAccessLocation();
            if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                continue;
            }
            DERIA5String derStr = (DERIA5String) DERIA5String
                    .getInstance((ASN1TaggedObject) name.toASN1Primitive(), false);
            String ocspUrl = derStr.getString();
            ocspUrls.add(ocspUrl);
        }

        return ocspUrls;
    }

    public static CertificateValidationStatus checkOcsp(X509Certificate certificate, X509Certificate issuer,
            String serviceUrl) throws Exception {
        OCSPReq request = generateOCSPRequest(issuer, certificate.getSerialNumber());
        OCSPResp ocspResponse = getOCSPResponse(serviceUrl, request);

        BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
        SingleResp[] responses = (basicResponse == null) ? null : basicResponse.getResponses();
        if (responses != null && responses.length == 1) {
            if (!isTrustworthy(basicResponse, request, certificate, issuer, serviceUrl)) {
                return CertificateValidationStatus.FAILED;
            }
            SingleResp resp = responses[0];
            Object status = resp.getCertStatus();
            if (status == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
                return CertificateValidationStatus.VALID;
            } else if (status instanceof RevokedStatus) {
                return CertificateValidationStatus.REVOKED;
            } else if (status instanceof UnknownStatus) {
                return CertificateValidationStatus.FAILED;
            }
        } else if (OCSPResponseStatus.SUCCESSFUL != ocspResponse.getStatus()) {
            throw new IOException(
                    "OCSP Request failed with status " + ocspResponseStatuses.get(ocspResponse.getStatus()));
        }
        return CertificateValidationStatus.FAILED;
    }

    /** Tells whether the response's single answer can be trusted, and logs the reason at WARN when it cannot. */
    private static boolean isTrustworthy(BasicOCSPResp response, OCSPReq request, X509Certificate certificate,
            X509Certificate issuer, String serviceUrl) {
        SingleResp answer = response.getResponses()[0];
        String reason;
        if (!isSignedByIssuerOrResponder(response, issuer)) {
            reason = "it is signed by neither the issuer nor an OCSP responder the issuer authorized";
        } else if (!isAbout(answer.getCertID(), request.getRequestList()[0].getCertID())) {
            reason = "it answers for another certificate";
        } else if (!isCurrent(answer)) {
            reason = "it is not current (thisUpdate %s, nextUpdate %s)"
                    .formatted(answer.getThisUpdate(), answer.getNextUpdate());
        } else if (!nonceMatches(response, request)) {
            reason = "its nonce differs from the request nonce";
        } else {
            return true;
        }
        String serialNumber = certificate.getSerialNumber().toString(16);
        logger.warn("Ignoring the OCSP response from {} for serial number {}: {}", serviceUrl, serialNumber, reason);
        return false;
    }

    private static boolean isSignedByIssuerOrResponder(BasicOCSPResp response, X509Certificate issuer) {
        return isSignedBy(response, issuer.getPublicKey()) || Arrays
                .stream(response.getCerts())
                .flatMap(candidate -> authorizedResponderKey(candidate, issuer).stream())
                .anyMatch(responderKey -> isSignedBy(response, responderKey));
    }

    private static boolean isSignedBy(BasicOCSPResp response, PublicKey key) {
        try {
            return response.isSignatureValid(new JcaContentVerifierProviderBuilder().build(key));
        } catch (OperatorCreationException | OCSPException e) {
            logger.debug("OCSP response signature does not verify with the key: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Returns the key of a certificate the issuer issued for signing OCSP responses (RFC 6960 section 4.2.2.2) that is
     * valid now and carries id-pkix-ocsp-nocheck: without it, the responder's own revocation would need checking, which
     * is not done here. Any other certificate yields nothing.
     */
    private static Optional<PublicKey> authorizedResponderKey(X509CertificateHolder candidate, X509Certificate issuer) {
        try {
            X509Certificate responder = CertificateUtil.getX509Certificate(candidate.getEncoded());
            responder.verify(issuer.getPublicKey());
            responder.checkValidity();
            List<String> purposes = Objects.requireNonNullElse(responder.getExtendedKeyUsage(), List.of());
            boolean[] keyUsage = responder.getKeyUsage();
            boolean authorized = responder.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                    && purposes.contains(KeyPurposeId.id_kp_OCSPSigning.getId())
                    && (keyUsage == null || keyUsage[DIGITAL_SIGNATURE])
                    && responder.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) != null;
            return authorized ? Optional.of(responder.getPublicKey()) : Optional.empty();
        } catch (GeneralSecurityException | IOException e) {
            logger.debug("OCSP response certificate is not an authorized responder: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private static boolean isAbout(CertificateID answered, CertificateID requested) {
        return answered.getSerialNumber().equals(requested.getSerialNumber())
                && answered.getHashAlgOID().equals(requested.getHashAlgOID())
                && Arrays.equals(answered.getIssuerNameHash(), requested.getIssuerNameHash())
                && Arrays.equals(answered.getIssuerKeyHash(), requested.getIssuerKeyHash());
    }

    private static boolean isCurrent(SingleResp answer) {
        Instant now = Instant.now();
        Instant thisUpdate = answer.getThisUpdate().toInstant();
        // An answer without nextUpdate is current only around its thisUpdate, as for the JDK's OCSP checker, so an old
        // one cannot be replayed.
        Instant validUntil = answer.getNextUpdate() == null ? thisUpdate : answer.getNextUpdate().toInstant();
        return !thisUpdate.isAfter(now.plus(CLOCK_SKEW)) && !validUntil.isBefore(now.minus(CLOCK_SKEW));
    }

    private static boolean nonceMatches(BasicOCSPResp response, OCSPReq request) {
        Extension responseNonce = response.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        return responseNonce == null || responseNonce
                .getExtnValue()
                .equals(request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue());
    }

    private static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
            throws OCSPException, OperatorException, CertificateEncodingException {
        JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
        DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
        CertificateID id = new CertificateID(digestCalculator, new JcaX509CertificateHolder(issuerCert), serialNumber);
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(id);
        Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                new DEROctetString(nonce.toByteArray()));
        gen.setRequestExtensions(new Extensions(new Extension[]{ext}));

        return gen.build();
    }

    private static OCSPResp getOCSPResponse(String serviceUrl, OCSPReq request) throws IOException {

        try {
            byte[] array = request.getEncoded();
            if (serviceUrl.startsWith("http")) {
                URL url = URI.create(serviceUrl).toURL();
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setConnectTimeout(ocspConnectTimeout);
                con.setReadTimeout(ocspReadTimeout);
                con.setRequestProperty("Content-Type", "application/ocsp-request");
                con.setRequestProperty("Accept", "application/ocsp-response");
                con.setDoOutput(true);
                OutputStream out = con.getOutputStream();
                DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
                dataOut.write(array);

                dataOut.flush();
                dataOut.close();

                // Get Response
                InputStream in = (InputStream) con.getContent();
                return new OCSPResp(in);
            } else {
                throw new IllegalArgumentException("Only http is supported for OCSP requests");
            }
        } catch (IOException e) {
            throw new IOException("Cannot get OCSP response from URL: " + serviceUrl, e);
        }
    }
}
