package com.otilm.core.certificate.type;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateFormat;
import com.otilm.api.model.core.certificate.CertificateFormatEncoding;
import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.api.model.core.certificate.CertificateRequestDetail;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.X509CertificateDetail;
import com.otilm.api.model.core.certificate.X509CertificateRequestDetail;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.attribute.CertificateRequestAttributeProjector;
import com.otilm.core.certificate.request.RenewContentSeeder;
import com.otilm.core.container.KeystoreDetection;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.CrmfCertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.util.CertificateRequestUtils;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.PlatformX500NameStyle;
import com.otilm.core.util.X509ObjectToString;
import com.otilm.core.util.X509RequestContentRenderer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import static org.bouncycastle.openssl.PEMParser.TYPE_CERTIFICATE;
import static org.bouncycastle.openssl.PEMParser.TYPE_PKCS7;
import static org.bouncycastle.openssl.PEMParser.TYPE_X509_CERTIFICATE;

/**
 * The handler of X.509 certificates, with PKCS#10 and CRMF requests. It puts the existing X.509 logic of
 * {@link CertificateUtil}, {@link CertificateRequestUtils} and the request models behind the handler interface and adds
 * no behavior of its own.
 */
@Component
public class X509CertificateTypeHandler implements CertificateTypeHandler {

    private static final Logger logger = LoggerFactory.getLogger(X509CertificateTypeHandler.class);

    private static final byte[] NOT_THIS_TYPE = new byte[0];
    private static final byte ASN1_SEQUENCE_TAG = 0x30;
    private static final Pattern PEM_HEADER_LINE = Pattern.compile("^[ \\t]*-----BEGIN ", Pattern.MULTILINE);
    private static final Set<String> REQUEST_PEM_TYPES = Set.of("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST");
    private static final Set<String> REQUEST_PEM_MARKERS = Set
            .of("-----BEGIN CERTIFICATE REQUEST-----", "-----BEGIN NEW CERTIFICATE REQUEST-----");

    private CryptographicOperationInternalService cryptographicOperationService;

    // signing a request goes through the key services, which reach back to the certificate services
    @Autowired
    public void setCryptographicOperationService(
            @Lazy CryptographicOperationInternalService cryptographicOperationService) {
        this.cryptographicOperationService = cryptographicOperationService;
    }

    @Override
    public String typeCode() {
        return CertificateType.X509.getCode();
    }

    @Override
    public Set<CertificateOperation> supportedOperations() {
        return EnumSet.allOf(CertificateOperation.class);
    }

    @Override
    public CertificateRequestFormat defaultRequestFormat() {
        return CertificateRequestFormat.PKCS10;
    }

    @Override
    public Optional<ParsedCertificate> parseCertificate(byte[] content) {
        if (KeystoreDetection.isKeystore(content)) {
            return Optional.empty();
        }
        byte[] der = decodeCertificateContent(content);
        if (der.length == 0) {
            return Optional.empty();
        }
        try {
            X509Certificate certificate = CertificateUtil.getX509Certificate(der);
            return Optional.of(new ParsedCertificate(typeCode(), certificate.getEncoded(), propertiesOf(certificate)));
        } catch (CertificateException | NoSuchAlgorithmException e) {
            logger.debug("The content is not an X.509 certificate: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public Optional<ParsedRequest> parseRequest(byte[] content) {
        byte[] der = decodeRequestContent(content);
        if (der.length == 0) {
            return Optional.empty();
        }
        CertificateRequest request = readRequest(der);
        if (request == null) {
            // a PEM that is labelled as a certificate request has been recognised, so a body that is none is invalid
            if (containsPemMarker(content)) {
                throw new CertificateTypeHandlerException(
                        "The PEM encoded certificate request holds neither a PKCS#10 nor a CRMF request");
            }
            return Optional.empty();
        }
        try {
            return Optional
                    .of(new ParsedRequest(typeCode(), request.getFormat(), request.getEncoded(),
                            request.getSubject() == null ? null : request.getSubject().toString(),
                            request.getPublicKey()));
        } catch (NoSuchAlgorithmException | CertificateRequestException e) {
            throw new CertificateTypeHandlerException(
                    "The X.509 certificate request has an unusable public key: " + e.getMessage());
        }
    }

    @Override
    public ParsedRequest readRequest(String content, CertificateRequestFormat format)
            throws CertificateRequestException {
        CertificateRequest request;
        try {
            request = CertificateRequestUtils.createCertificateRequest(content, format);
        } catch (IllegalArgumentException e) {
            // the cause carries the wording of the Base64 decoder, which is not meant for the client
            throw new CertificateRequestException("The content is not a certificate request in Base64");
        }
        return new ParsedRequest(typeCode(), request.getFormat(), request.getEncoded(),
                request.getSubject() == null ? null : request.getSubject().toString(), publicKeyOrNull(request));
    }

    // a key that cannot be decoded is refused by the check that needs it, not by reading the request
    private static PublicKey publicKeyOrNull(CertificateRequest request) {
        try {
            return request.getPublicKey();
        } catch (NoSuchAlgorithmException | CertificateRequestException e) {
            logger.debug("The public key of the certificate request cannot be decoded: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String generateRequest(List<DataAttributeV3> definitions, List<RequestAttribute> requestAttributes,
            CertificateRequestFormat format, RequestSigning signing) throws NotFoundException, CertificateException {
        // TODO: support for the CRMF should be handled also in case it should be generated
        if (format == CertificateRequestFormat.CRMF) {
            throw new CertificateException("CRMF format is not supported for CSR generation");
        }
        X509RequestContent requestContent = CertificateRequestAttributeProjector
                .project(definitions, requestAttributes);
        Extensions extensions;
        try {
            extensions = X509RequestContentRenderer.toExtensions(requestContent);
        } catch (IOException e) {
            logger.error("Failed to build CSR extensions", e);
            throw new CertificateException("Failed to build CSR extensions", e);
        }
        X500Principal principal;
        try {
            principal = X509RequestContentRenderer.toX500Principal(requestContent);
        } catch (IOException e) {
            logger.error("Failed to build CSR subject", e);
            throw new CertificateException("Failed to build CSR subject", e);
        }
        return sign(principal, extensions, signing);
    }

    @Override
    public String generateRekeyRequest(ParsedCertificate current, RequestSigning signing) throws NotFoundException {
        // TODO: implement support for CRMF, currently only PKCS10 is supported
        X509Certificate certificate = x509Of(current);
        if (certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId()) != null
                && signing.altKeyUuid() == null) {
            throw new ValidationException("Missing alternative key for re-keying of hybrid certificate");
        }
        return sign(certificate.getSubjectX500Principal(), RenewContentSeeder.rekeySanExtensions(certificate), signing);
    }

    @Override
    public void requireSameKey(ParsedRequest request, ParsedCertificate current) {
        try {
            X509Certificate certificate = x509Of(current);
            CertificateRequest certificateRequest = x509Of(request);
            if (!Arrays
                    .equals(certificate.getPublicKey().getEncoded(), certificateRequest.getPublicKey().getEncoded())) {
                throw new ValidationException("Public key of certificate and CSR does not match");
            }
            checkMatchingAlternativePublicKey(certificateRequest, certificate);
        } catch (Exception e) {
            throw new ValidationException(ValidationError
                    .create("Unable to validate the public key of CSR and certificate. Error: " + e.getMessage()));
        }
    }

    @Override
    public void checkRekeyRequest(ParsedRequest request, ParsedCertificate current) {
        X509Certificate certificate = x509Of(current);
        try {
            CertificateRequest certificateRequest = x509Of(request);
            if (Arrays
                    .equals(certificate.getPublicKey().getEncoded(), certificateRequest.getPublicKey().getEncoded())) {
                throw new ValidationException("Public key of certificate and CSR are same");
            }
            checkNotMatchingAlternativePublicKey(certificateRequest, certificate);
        } catch (Exception e) {
            throw new ValidationException(ValidationError
                    .create("Unable to validate the public key of CSR and certificate. Error: " + e.getMessage()));
        }
        checkSameSubject(request, certificate);
    }

    @Override
    public boolean verifySignature(ParsedCertificate certificate, ParsedCertificate issuer) {
        try {
            X509Certificate subject = CertificateUtil.getX509Certificate(certificate.encoded());
            X509Certificate signer = issuer == null ? subject : CertificateUtil.getX509Certificate(issuer.encoded());
            subject.verify(signer.getPublicKey());
            return true;
        } catch (Exception e) {
            logger.debug("Unable to verify certificate for signature", e);
            return false;
        }
    }

    /** Whether the alternative signature of a hybrid certificate is valid for the issuer's alternative key. */
    public boolean verifyAlternativeSignature(ParsedCertificate certificate, ParsedCertificate issuer) {
        try {
            X509Certificate subject = CertificateUtil.getX509Certificate(certificate.encoded());
            X509Certificate signer = issuer == null ? subject : CertificateUtil.getX509Certificate(issuer.encoded());
            return new JcaX509CertificateHolder(subject)
                    .isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder()
                            .build(CertificateUtil
                                    .getAltPublicKey(
                                            signer.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId()))));
        } catch (Exception e) {
            logger.debug("Unable to verify certificate for alternative signature", e);
            return false;
        }
    }

    @Override
    public boolean verifySignature(ParsedRequest request, ParsedCertificate current) {
        try {
            CertificateRequest parsed = CertificateRequestUtils
                    .createCertificateRequest(request.encoded(), request.format());
            if (parsed instanceof Pkcs10CertificateRequest pkcs10) {
                PublicKey publicKey = CryptographyUtil.decodePublicKey(pkcs10.getJcaObject().getSubjectPublicKeyInfo());
                return pkcs10
                        .getJcaObject()
                        .isSignatureValid(new JcaContentVerifierProviderBuilder()
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                .build(publicKey));
            }
            CrmfCertificateRequest crmf = (CrmfCertificateRequest) parsed;
            return crmf.getCertificateRequestMessage().hasProofOfPossession() && crmf
                    .getCertificateRequestMessage()
                    .isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(request.publicKey()));
        } catch (Exception e) {
            logger.debug("Unable to verify the signature of the certificate request", e);
            return false;
        }
    }

    @Override
    public boolean isIssuedBy(ParsedCertificate certificate, ParsedCertificate issuer) {
        try {
            X509Certificate subject = CertificateUtil.getX509Certificate(certificate.encoded());
            X509Certificate signer = CertificateUtil.getX509Certificate(issuer.encoded());
            return subject.getIssuerX500Principal().equals(signer.getSubjectX500Principal())
                    && verifySignature(certificate, issuer);
        } catch (CertificateException e) {
            return false;
        }
    }

    @Override
    public Set<CertificateFormat> downloadFormats() {
        return EnumSet.of(CertificateFormat.RAW, CertificateFormat.PKCS7);
    }

    @Override
    public byte[] encode(List<ParsedCertificate> certificates, CertificateFormat format,
            CertificateFormatEncoding encoding) {
        if (format == CertificateFormat.RAW && encoding == CertificateFormatEncoding.DER && certificates.size() > 1) {
            throw new CertificateTypeHandlerException("DER encoding of raw format holds one certificate only.");
        }
        try {
            List<X509Certificate> x509Certificates = new ArrayList<>();
            for (ParsedCertificate certificate : certificates) {
                x509Certificates.add(CertificateUtil.getX509Certificate(certificate.encoded()));
            }
            if (format == CertificateFormat.RAW) {
                return encoding == CertificateFormatEncoding.DER
                        ? x509Certificates.getFirst().getEncoded()
                        : toPem(x509Certificates);
            }
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addCertificates(new JcaCertStore(x509Certificates));
            byte[] pkcs7 = generator.generate(new CMSProcessableByteArray(new byte[0])).getEncoded();
            return encoding == CertificateFormatEncoding.PEM ? toPem("PKCS7", pkcs7) : pkcs7;
        } catch (Exception e) {
            throw new CertificateTypeHandlerException(
                    "Could not encode the X.509 certificate as " + format + ": " + e.getMessage());
        }
    }

    @Override
    public Certificate stampIssued(Certificate certificate, ParsedCertificate issued) {
        X509CertificateEntity entity = X509CertificateEntity.from(certificate);
        CertificateUtil.stampIssuedFields(entity, x509Of(issued));
        return entity;
    }

    @Override
    public String contentToStore(ParsedCertificate certificate) {
        return X509ObjectToString.toPem(x509Of(certificate));
    }

    /** Shows the extended key usages by the display names of their OIDs, where a name is known. */
    @Override
    public void presentDetail(CertificateDetail detail) {
        if (!(detail instanceof X509CertificateDetail x509Detail) || x509Detail.getExtendedKeyUsage() == null) {
            return;
        }
        Map<String, OidRecord> oidToName = OidHandler.getOidCache(OidCategory.EXTENDED_KEY_USAGE);
        if (oidToName == null) {
            return;
        }
        x509Detail
                .setExtendedKeyUsage(x509Detail
                        .getExtendedKeyUsage()
                        .stream()
                        .map(oid -> oidToName.get(oid) != null ? oidToName.get(oid).displayName() : oid)
                        .toList());
    }

    @Override
    public void setAlternativeSignatureAttributes(CertificateRequestDetail request,
            List<ResponseAttribute> attributes) {
        if (request instanceof X509CertificateRequestDetail x509Request) {
            x509Request.setAltSignatureAttributes(attributes);
        }
    }

    /** Reads an already parsed X.509 certificate the way {@link #parseCertificate(byte[])} reads its encoding. */
    public ParsedCertificate describe(X509Certificate certificate) throws CertificateException {
        try {
            return new ParsedCertificate(typeCode(), certificate.getEncoded(), propertiesOf(certificate));
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateException(e);
        }
    }

    private String sign(X500Principal principal, Extensions extensions, RequestSigning signing)
            throws NotFoundException {
        try {
            return cryptographicOperationService
                    .generateCsr(signing.keyUuid(), signing.tokenProfileUuid(), principal, extensions,
                            signing.signatureAttributes(), signing.altKeyUuid(), signing.altTokenProfileUuid(),
                            signing.altSignatureAttributes());
        } catch (InvalidKeySpecException | IOException | NoSuchAlgorithmException | AttributeException e) {
            throw new ValidationException(
                    ValidationError.create("Failed to generate the CSR. Error: " + e.getMessage()));
        }
    }

    private static void checkMatchingAlternativePublicKey(CertificateRequest certificateRequest,
            X509Certificate certificate)
            throws NoSuchAlgorithmException, CertificateRequestException, IOException, InvalidKeySpecException {
        byte[] altKeyEncoded = certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
        PublicKey altKeyCsr = certificateRequest.getAltPublicKey();
        if (altKeyEncoded == null && altKeyCsr != null) {
            throw new ValidationException(
                    "Certificate request contains alternative key, but the certificate does not.");
        }
        if (altKeyEncoded != null && altKeyCsr == null) {
            throw new ValidationException(
                    "Certificate request does not contain alternative key, but the certificate does.");
        } else if (altKeyCsr != null) {
            PublicKey altPublicKey = CertificateUtil.getAltPublicKey(altKeyEncoded);
            if (!Arrays.equals(altPublicKey.getEncoded(), certificateRequest.getAltPublicKey().getEncoded())) {
                throw new ValidationException("Alternative Public keys of certificate and CSR do not match");
            }
        }
    }

    private static void checkNotMatchingAlternativePublicKey(CertificateRequest certificateRequest,
            X509Certificate certificate)
            throws NoSuchAlgorithmException, CertificateRequestException, IOException, InvalidKeySpecException {
        byte[] altKeyEncoded = certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
        PublicKey altKeyCsr = certificateRequest.getAltPublicKey();
        if (altKeyCsr == null && altKeyEncoded != null) {
            throw new ValidationException("Certificate contains alternative key, but CSR does not.");
        }
        if (altKeyEncoded != null) {
            PublicKey altPublicKey = CertificateUtil.getAltPublicKey(altKeyEncoded);
            if (Arrays.equals(altPublicKey.getEncoded(), certificateRequest.getAltPublicKey().getEncoded())) {
                throw new ValidationException("Alternative Public keys of certificate and CSR should not match");
            }
        }
    }

    private static void checkSameSubject(ParsedRequest request, X509Certificate certificate) {
        try {
            // convert subjects to normalized form to compare them
            String normalizedRequestSubject = X500Name
                    .getInstance(new PlatformX500NameStyle(true), x509Of(request).getSubject().getEncoded())
                    .toString();
            String normalizedCertificateSubject = X500Name
                    .getInstance(new PlatformX500NameStyle(true), certificate.getSubjectX500Principal().getEncoded())
                    .toString();
            if (!normalizedCertificateSubject.equals(normalizedRequestSubject)) {
                throw new ValidationException("Subject DN of certificate and CSR does not match");
            }
        } catch (Exception e) {
            throw new ValidationException(ValidationError
                    .create("Unable to validate the Subject DN of CSR and certificate. Error: " + e.getMessage()));
        }
    }

    private static CertificateRequest x509Of(ParsedRequest request) throws CertificateRequestException {
        return CertificateRequestUtils.createCertificateRequest(request.encoded(), request.format());
    }

    private static X509Certificate x509Of(ParsedCertificate certificate) {
        try {
            return CertificateUtil.getX509Certificate(certificate.encoded());
        } catch (CertificateException e) {
            throw new CertificateTypeHandlerException("The content is not an X.509 certificate");
        }
    }

    /** The validity of an X.509 certificate, which always has a time. */
    public static Validity validityOf(X509Certificate certificate) {
        return new Validity(certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant(),
                ValidityPrecision.DATE_TIME);
    }

    private static CertificateProperties propertiesOf(X509Certificate certificate)
            throws CertificateException, NoSuchAlgorithmException {
        Validity validity = validityOf(certificate);
        return new CertificateProperties(certificate.getSerialNumber().toString(16),
                certificate.getIssuerX500Principal().getName(), certificate.getSubjectX500Principal().getName(),
                validity, certificate.getPublicKey(), CertificateUtil.getThumbprint(certificate.getEncoded()));
    }

    private static byte[] decodeCertificateContent(byte[] content) {
        if (looksLikeDer(content) || !containsPemMarker(content)) {
            return content;
        }
        // the first PEM object decides, wherever it starts, as the parser of the upload has always read it
        try (PEMParser pemParser = new PEMParser(new StringReader(new String(content, StandardCharsets.UTF_8)))) {
            PemObject pemObject = pemParser.readPemObject();
            if (pemObject != null && (TYPE_CERTIFICATE.equals(pemObject.getType())
                    || TYPE_X509_CERTIFICATE.equals(pemObject.getType()) || TYPE_PKCS7.equals(pemObject.getType()))) {
                return pemObject.getContent();
            }
        } catch (IOException e) {
            logger.debug("Failed to read the content as a PEM object: {}", e.getMessage());
        }
        return NOT_THIS_TYPE;
    }

    private static byte[] decodeRequestContent(byte[] content) {
        if (looksLikeDer(content) || !containsPemMarker(content)) {
            return content;
        }
        String pem = new String(content, StandardCharsets.UTF_8);
        if (REQUEST_PEM_MARKERS.stream().noneMatch(pem::contains)) {
            return NOT_THIS_TYPE;
        }
        try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
            PemObject pemObject = pemParser.readPemObject();
            if (pemObject != null && REQUEST_PEM_TYPES.contains(pemObject.getType())) {
                return pemObject.getContent();
            }
            // header, body and footer that share a line are not a PEM object to the parser
            return CertificateRequestUtils.normalizeAndDecodeCsr(pem);
        } catch (IOException | IllegalArgumentException | DecoderException e) {
            throw new CertificateTypeHandlerException(
                    "The PEM encoded certificate request is malformed: " + e.getMessage());
        }
    }

    private static CertificateRequest readRequest(byte[] der) {
        try {
            return new Pkcs10CertificateRequest(der);
        } catch (CertificateRequestException notPkcs10) {
            try {
                return new CrmfCertificateRequest(der);
            } catch (CertificateRequestException notCrmf) {
                return null;
            }
        }
    }

    // content that is one complete ASN.1 structure is DER, whatever text its fields hold
    private static boolean looksLikeDer(byte[] content) {
        if (content.length == 0 || content[0] != ASN1_SEQUENCE_TAG) {
            return false;
        }
        try {
            ASN1Primitive.fromByteArray(content);
            return true;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    // a PEM header starts a line, as the PEM reader requires, so binary content that merely holds the text is not PEM
    private static boolean containsPemMarker(byte[] content) {
        return PEM_HEADER_LINE.matcher(new String(content, StandardCharsets.ISO_8859_1)).find();
    }

    private static byte[] toPem(List<X509Certificate> certificates) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (JcaPEMWriter writer = new JcaPEMWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8))) {
            for (X509Certificate certificate : certificates) {
                writer.writeObject(certificate);
            }
        }
        return out.toByteArray();
    }

    private static byte[] toPem(String type, byte[] content) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (PemWriter writer = new PemWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8))) {
            writer.writeObject(new PemObject(type, content));
        }
        return out.toByteArray();
    }
}
