package com.czertainly.core.util;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.core.attribute.CsrAttributes;
import com.czertainly.core.model.request.CertificateRequest;
import com.czertainly.core.model.request.CrmfCertificateRequest;
import com.czertainly.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

public class CertificateRequestUtils {
    private static final Logger logger = LoggerFactory.getLogger(CertificateRequestUtils.class);

    public static JcaPKCS10CertificationRequest csrStringToJcaObject(String csr) throws IOException {
        csr = normalizeCsrContent(csr);
        logger.debug("Decoding Base64-encoded CSR: {}", csr);
        byte[] decoded = Base64.getDecoder().decode(csr);
        return new JcaPKCS10CertificationRequest(decoded);
    }

    /**
     * Function to convert the content from bytearray to string
     * @param encoded Encoded content
     * @return CSR String
     * @throws IOException when there is an issue reading the content
     */
    public static String byteArrayCsrToString(byte[] encoded) throws IOException {
        PemObject pemObject = new PemObject("CERTIFICATE REQUEST", encoded);
        StringWriter str = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(str);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        str.close();
        return normalizeCsrContent(str.toString());
    }


    public static PublicKey publicKeyObjectFromString(String publicKey, String pqcAlgorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicBytes = Base64.getDecoder().decode(publicKey);

        PublicKey publicKeyObject;
        try {
            String oid = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(publicBytes)
                    .getAlgorithm().getAlgorithm().toString();
            publicKeyObject = KeyFactory.getInstance(oid, new org.bouncycastle.jce.provider.BouncyCastleProvider())
                    .generatePublic(new X509EncodedKeySpec(publicBytes));
        } catch (NoSuchAlgorithmException e) {
            try {

                publicKeyObject = KeyFactory.getInstance(pqcAlgorithm, BouncyCastlePQCProvider.PROVIDER_NAME)
                        .generatePublic(new X509EncodedKeySpec(publicBytes));
            } catch (Exception e1){
                logger.error(e1.getMessage());
                throw new NoSuchAlgorithmException();
            }
        }
        return publicKeyObject;
    }

    public static X500Principal buildSubject(List<RequestAttribute> attributes) {

        // Get the data for the attributes
        String commonName = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        CsrAttributes.COMMON_NAME_ATTRIBUTE_NAME,
                        attributes,
                        StringAttributeContentV2.class)
                .getData();

        String organizationalUnit = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        CsrAttributes.ORGANIZATION_UNIT_ATTRIBUTE_NAME,
                        attributes,
                        StringAttributeContentV2.class)
                .getData();

        String organization = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        CsrAttributes.ORGANIZATION_ATTRIBUTE_NAME,
                        attributes,
                        StringAttributeContentV2.class)
                .getData();

        String locality = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        CsrAttributes.LOCALITY_ATTRIBUTE_NAME,
                        attributes,
                        StringAttributeContentV2.class)
                .getData();

        String state = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        CsrAttributes.STATE_ATTRIBUTE_NAME,
                        attributes,
                        StringAttributeContentV2.class)
                .getData();

        String country = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        CsrAttributes.COUNTRY_ATTRIBUTE_NAME,
                        attributes,
                        StringAttributeContentV2.class)
                .getData();

        StringBuilder nameBuilder = new StringBuilder();
        if (commonName != null) {
            nameBuilder.append("CN=").append(escapeSpecialCharacters(commonName));
        }
        if (organizationalUnit != null) {
            nameBuilder.append(", OU=").append(escapeSpecialCharacters(organizationalUnit));
        }
        if (organization != null) {
            nameBuilder.append(", O=").append(escapeSpecialCharacters(organization));
        }
        if (locality != null) {
            nameBuilder.append(", L=").append(escapeSpecialCharacters(locality));
        }
        if (state != null) {
            nameBuilder.append(", ST=").append(escapeSpecialCharacters(state));
        }
        if (country != null) {
            nameBuilder.append(", C=").append(escapeSpecialCharacters(country));
        }
        return new X500Principal(nameBuilder.toString());
    }


    // Escape special characters according to RFC 2253
    private static String escapeSpecialCharacters(String inputString) {
        // Escape one of the characters ",", "+", """, "\", "<", ">" or ";"
        final String[] specialCharacters = {"\\", ",", "+", "\"", "<", ">" , ";"};
        for (String specialCharacter : specialCharacters) {
            if (inputString.contains(specialCharacter)) {
                inputString = inputString.replace(specialCharacter, "\\" + specialCharacter);
            }
        }

        // Escape a space character occurring at the end of the string
        if (inputString.endsWith(" ")) inputString = inputString.substring(0, inputString.length() -1 ) + "\\ ";

        // Escape a space or "#" character occurring at the beginning of the string
        if (inputString.startsWith("#") || inputString.startsWith(" ")) return "\\" + inputString;

        return inputString;
    }

    /**
     * Normalize and decode the CSR byte array content when there can be different headers and footers
     * in Base64-encoded CSR content
     * @param csr CSR content in byte array
     * @return Normalized Base64-decoded CSR content without headers and footers and new lines
     */
    public static byte[] normalizeAndDecodeCsr(byte[] csr) {
        return normalizeAndDecodeCsr(new String(csr));
    }

    /**
     * Normalize and decode the CSR content when there can be different headers and footers
     * in Base64-encoded CSR content
     * @param csr CSR content in string
     * @return Normalized Base64-decoded CSR content without headers and footers and new lines
     */
    public static byte[] normalizeAndDecodeCsr(String csr) {
        String normalizedCsr = normalizeCsrContent(csr);
        return Base64.getDecoder().decode(normalizedCsr);
    }

    /**
     * Normalize the CSR content when there can be different headers and footers
     * in Base64-encoded CSR content
     * @param csr CSR content in string
     * @return Normalized Base64-encoded CSR content without headers and footers and new lines
     */
    public static String normalizeCsrContent(String csr) {
        // some of the X.509 CSRs can have different headers and footers
        csr = csr.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----BEGIN NEW CERTIFICATE REQUEST-----", "")
                .replace("\r", "").replace("\n", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replace("-----END NEW CERTIFICATE REQUEST-----", "");
        return csr;
    }

    /**
     * Create a certificate request object from Base64-encoded string
     * The request can be PEM, and we are trying to decode double encoded content
     * @param certificateRequest Base64-encoded certificate request (it can be PEM, or double Base64 encoded)
     * @param format Format of the certificate request as {@link CertificateRequestFormat}
     * @return {@link CertificateRequest}
     * @throws CertificateRequestException when there is an issue creating the certificate request
     */
    public static CertificateRequest createCertificateRequest(String certificateRequest, CertificateRequestFormat format) throws CertificateRequestException {
        switch (format) {
            case PKCS10, CRMF -> {
                byte[] decoded = normalizeAndDecodeCsr(certificateRequest);
                try {
                    return createCertificateRequest(decoded, format);
                } catch (CertificateRequestException e) {
                    // try to decode the content again
                    decoded = normalizeAndDecodeCsr(decoded);
                    return createCertificateRequest(decoded, format);
                }
            }
            default -> throw new IllegalArgumentException("Unsupported certificate request format: " + format);
        }
    }

    /**
     * Create a certificate request object from byte array and format
     * @param certificateRequest DER encoded certificate request
     * @param format Format of the certificate request according to {@link CertificateRequestFormat}
     * @return {@link CertificateRequest}
     * @throws CertificateRequestException when there is an issue creating the certificate request
     */
    public static CertificateRequest createCertificateRequest(byte[] certificateRequest, CertificateRequestFormat format) throws CertificateRequestException {
        switch (format) {
            case PKCS10 -> {
                return new Pkcs10CertificateRequest(certificateRequest);
            }
            case CRMF -> {
                return new CrmfCertificateRequest(certificateRequest);
            }
            default -> throw new IllegalArgumentException("Unsupported certificate request format: " + format);
        }
    }

}
