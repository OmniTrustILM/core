package com.otilm.core.certificate.type;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.model.client.attribute.ResponseAttribute;
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
import com.otilm.core.container.KeystoreDetection;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.CrmfCertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.util.CertificateRequestUtils;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.CryptographyUtil;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Extension;
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

    private static CertificateProperties propertiesOf(X509Certificate certificate)
            throws CertificateException, NoSuchAlgorithmException {
        Validity validity = new Validity(certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant(),
                ValidityPrecision.DATE_TIME);
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
