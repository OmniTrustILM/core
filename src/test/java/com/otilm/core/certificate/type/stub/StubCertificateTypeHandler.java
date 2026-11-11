package com.otilm.core.certificate.type.stub;

import com.otilm.api.model.core.certificate.CertificateFormat;
import com.otilm.api.model.core.certificate.CertificateFormatEncoding;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.certificate.type.CertificateOperation;
import com.otilm.core.certificate.type.CertificateProperties;
import com.otilm.core.certificate.type.CertificateTypeDetails;
import com.otilm.core.certificate.type.CertificateTypeHandler;
import com.otilm.core.certificate.type.CertificateTypeHandlerException;
import com.otilm.core.certificate.type.ParsedCertificate;
import com.otilm.core.certificate.type.ParsedRequest;
import com.otilm.core.certificate.type.Validity;
import com.otilm.core.certificate.type.ValidityPrecision;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A certificate type that exists only in tests: validity in whole days, no revocation and no chain. It shows that a
 * type is added by this one class and its own package, registered as a bean where a test needs it.
 */
public class StubCertificateTypeHandler implements CertificateTypeHandler {

    public static final String TYPE_CODE = "STUB";

    private static final String CERTIFICATE_PREFIX = "STUB-CERT|";
    private static final String REQUEST_PREFIX = "STUB-REQ|";

    @Override
    public String typeCode() {
        return TYPE_CODE;
    }

    @Override
    public Set<CertificateOperation> supportedOperations() {
        return EnumSet.of(CertificateOperation.RENEW, CertificateOperation.COMPLIANCE);
    }

    @Override
    public CertificateRequestFormat defaultRequestFormat() {
        return CertificateRequestFormat.PKCS10;
    }

    @Override
    public Optional<ParsedCertificate> parseCertificate(byte[] content) {
        String text = new String(content, StandardCharsets.UTF_8);
        if (!text.startsWith(CERTIFICATE_PREFIX)) {
            return Optional.empty();
        }
        String[] fields = text.split("\\|");
        if (fields.length != 6) {
            throw new CertificateTypeHandlerException("A stub certificate has six fields, found " + fields.length);
        }
        Validity validity = new Validity(startOfDay(fields[3]), startOfDay(fields[4]), ValidityPrecision.DATE);
        CertificateProperties properties = new CertificateProperties(fields[1], null, fields[2], validity,
                publicKey(fields[5]), Integer.toHexString(text.hashCode()));
        return Optional.of(new ParsedCertificate(TYPE_CODE, content, properties));
    }

    @Override
    public Optional<ParsedRequest> parseRequest(byte[] content) {
        String text = new String(content, StandardCharsets.UTF_8);
        if (!text.startsWith(REQUEST_PREFIX)) {
            return Optional.empty();
        }
        String[] fields = text.split("\\|");
        return Optional
                .of(new ParsedRequest(TYPE_CODE, CertificateRequestFormat.PKCS10, content, fields[1],
                        publicKey(fields[2])));
    }

    @Override
    public boolean verifySignature(ParsedCertificate certificate, ParsedCertificate issuer) {
        return true;
    }

    @Override
    public boolean verifySignature(ParsedRequest request, ParsedCertificate current) {
        String[] fields = new String(request.encoded(), StandardCharsets.UTF_8).split("\\|");
        boolean signed = Boolean.parseBoolean(fields[3]);
        return signed && (current == null || fields[4].equals(current.properties().identifier()));
    }

    @Override
    public boolean isIssuedBy(ParsedCertificate certificate, ParsedCertificate issuer) {
        return false;
    }

    @Override
    public Set<CertificateFormat> downloadFormats() {
        return Set.of(CertificateFormat.RAW);
    }

    @Override
    public byte[] encode(ParsedCertificate certificate, CertificateFormat format, CertificateFormatEncoding encoding) {
        return certificate.encoded();
    }

    @Override
    public Optional<CertificateTypeDetails> describeDetails(ParsedCertificate certificate) {
        return Optional.of(new CertificateTypeDetails(TYPE_CODE, Map.of("holder", certificate.properties().holder())));
    }

    private static Instant startOfDay(String date) {
        return LocalDate.parse(date).atStartOfDay(ZoneOffset.UTC).toInstant();
    }

    private static PublicKey publicKey(String encoded) {
        try {
            return KeyFactory
                    .getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encoded)));
        } catch (Exception e) {
            throw new CertificateTypeHandlerException("A stub certificate carries an invalid public key");
        }
    }
}
