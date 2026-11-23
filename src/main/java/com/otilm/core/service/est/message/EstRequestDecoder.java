package com.otilm.core.service.est.message;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.SignatureVerificationBounds;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;

/**
 * Decodes the body of an EST enrollment request: the base64 text of one DER PKCS#10 certification request (RFC 7030
 * section 4.2.1). Carriage returns, line feeds, spaces and tabs are ignored (RFC 8951); any other character outside the
 * base64 alphabet is refused, the URL-safe ones and PEM armour included.
 */
@Slf4j
public final class EstRequestDecoder {

    private EstRequestDecoder() {
    }

    /**
     * Decodes the request without verifying its signature, which {@link #verifyProofOfPossession} does. A
     * {@code challengePassword} attribute is neither read nor refused.
     *
     * @param body the request body
     * @return the request, whose subject and subject alternative names can be read
     * @throws EstException {@link EstError#BAD_REQUEST} when the body is not the base64 text of exactly one DER
     * request, when {@link SignatureVerificationBounds#requireBoundedRequest} refuses its keys, its alternative keys or
     * its signature algorithm, when its extension request cannot be read, or when a subject alternative name it asks
     * for cannot be rendered
     */
    public static Pkcs10CertificateRequest decode(byte[] body) {
        byte[] der = decodeBase64(body);
        Pkcs10CertificateRequest request = parseDer(der);
        requireBoundedRequest(request);
        requireReadableSubjectAlternativeNames(request);
        return request;
    }

    /**
     * Verifies the signature of the request with the key it carries, which proves possession of the private key.
     *
     * @param request a request that {@link #decode} returned
     * @throws EstException {@link EstError#INVALID_SIGNATURE} when the signature does not verify or cannot be checked,
     * because its algorithm or the key is not supported
     */
    public static void verifyProofOfPossession(Pkcs10CertificateRequest request) {
        boolean verified;
        try {
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(request.getPublicKey());
            verified = request.getJcaObject().isSignatureValid(verifierProvider);
        } catch (NoSuchAlgorithmException | CertificateRequestException | OperatorCreationException | PKCSException
                | RuntimeException e) {
            // BouncyCastle reports a malformed signature value with an unchecked exception
            throw refused(EstError.INVALID_SIGNATURE, "the signature cannot be checked");
        }
        if (!verified) {
            throw refused(EstError.INVALID_SIGNATURE, "the signature does not verify");
        }
    }

    private static byte[] decodeBase64(byte[] body) {
        try {
            return Base64.getDecoder().decode(withoutBlanks(body));
        } catch (IllegalArgumentException e) {
            throw refused(EstError.BAD_REQUEST, "the body is not base64 text");
        }
    }

    private static byte[] withoutBlanks(byte[] body) {
        byte[] stripped = new byte[body.length];
        int length = 0;
        for (byte character : body) {
            if (character != '\r' && character != '\n' && character != ' ' && character != '\t') {
                stripped[length++] = character;
            }
        }
        return Arrays.copyOf(stripped, length);
    }

    /**
     * Parsing rejects data after the request, but accepts BER, so the request is DER only when its canonical encoding
     * is the input.
     */
    private static Pkcs10CertificateRequest parseDer(byte[] der) {
        Pkcs10CertificateRequest request;
        byte[] canonical;
        try {
            request = new Pkcs10CertificateRequest(der);
            canonical = request.getJcaObject().toASN1Structure().getEncoded(ASN1Encoding.DER);
        } catch (CertificateRequestException | IOException e) {
            throw refused(EstError.BAD_REQUEST, "the body is not one PKCS#10 certification request");
        }
        if (!Arrays.equals(canonical, der)) {
            throw refused(EstError.BAD_REQUEST, "the request is not DER encoded");
        }
        return request;
    }

    /**
     * Judges the keys and the signature algorithm by their encoding and builds no key: proving possession builds the
     * key of a client that may be no more than identified.
     */
    private static void requireBoundedRequest(Pkcs10CertificateRequest request) {
        try {
            SignatureVerificationBounds.requireBoundedRequest(request.getJcaObject());
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw refused(EstError.BAD_REQUEST, e.getMessage());
        }
    }

    /**
     * Parsing does not read the attributes of the request. The subject alternative names come from the extension
     * request, so a request whose extension request cannot be read would make every reader of them fail.
     * {@link CertificateUtil#getSAN} leaves out a name that it cannot render, so a request is refused unless every name
     * it asks for is rendered: what is compared and what is issued is then what it asks for.
     */
    private static void requireReadableSubjectAlternativeNames(Pkcs10CertificateRequest request) {
        int requested;
        int rendered;
        try {
            requested = subjectAlternativeNamesOf(request).length;
            rendered = CertificateUtil.getSAN(request).values().stream().mapToInt(List::size).sum();
        } catch (RuntimeException e) {
            throw refused(EstError.BAD_REQUEST,
                    "the extension request cannot be read: " + e.getClass().getSimpleName());
        }
        if (rendered != requested) {
            throw refused(EstError.BAD_REQUEST,
                    (requested - rendered) + " of " + requested + " subject alternative names cannot be rendered");
        }
    }

    /**
     * @return the names of the subject alternative name extension, read from the extension request as
     * {@link CertificateUtil#getSAN} reads them
     */
    private static GeneralName[] subjectAlternativeNamesOf(Pkcs10CertificateRequest request) {
        Extensions extensions = requestedExtensions(request.getJcaObject());
        if (extensions == null) {
            return new GeneralName[0];
        }
        GeneralNames names = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        return names == null ? new GeneralName[0] : names.getNames();
    }

    /**
     * @return the extensions of the first {@code extensionRequest} attribute; {@code null} when there is none
     */
    static Extensions requestedExtensions(PKCS10CertificationRequest request) {
        Attribute[] extensionRequests = request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (extensionRequests.length == 0) {
            return null;
        }
        return Extensions.getInstance(extensionRequests[0].getAttrValues().getObjectAt(0));
    }

    private static EstException refused(EstError error, String reason) {
        log.debug("EST request refused as {}: {}", error, reason);
        return new EstException(error);
    }
}
