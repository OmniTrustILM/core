package com.otilm.core.util;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.certificate.*;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.api.model.core.settings.CertificateValidationSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.CrmfCertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.settings.SettingsCache;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.annotation.Nullable;
import jakarta.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

public class CertificateUtil {
    public static final String EMPTY_COMMON_NAME_PLACEHOLDER = "<empty>";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    private static final Map<String, KeyAlgorithm> CERTIFICATE_ALGORITHM_FROM_PROVIDER = new HashMap<>();
    private static final Logger logger = LoggerFactory.getLogger(CertificateUtil.class);
    private static final Map<Integer, String> SAN_TYPE_MAP = new HashMap<>();

    static {
        SAN_TYPE_MAP.put(GeneralName.otherName, "otherName");
        SAN_TYPE_MAP.put(GeneralName.rfc822Name, "rfc822Name");
        SAN_TYPE_MAP.put(GeneralName.dNSName, "dNSName");
        SAN_TYPE_MAP.put(GeneralName.x400Address, "x400Address");
        SAN_TYPE_MAP.put(GeneralName.directoryName, "directoryName");
        SAN_TYPE_MAP.put(GeneralName.ediPartyName, "ediPartyName");
        SAN_TYPE_MAP.put(GeneralName.uniformResourceIdentifier, "uniformResourceIdentifier");
        SAN_TYPE_MAP.put(GeneralName.iPAddress, "iPAddress");
        SAN_TYPE_MAP.put(GeneralName.registeredID, "registeredID");
    }

    static {
        CERTIFICATE_ALGORITHM_FROM_PROVIDER.put("RSA", KeyAlgorithm.RSA);
        CERTIFICATE_ALGORITHM_FROM_PROVIDER.put("EC", KeyAlgorithm.ECDSA);
        CERTIFICATE_ALGORITHM_FROM_PROVIDER.put("Falcon", KeyAlgorithm.FALCON);
    }

    private CertificateUtil() {
    }

    public static String formatCommonName(String commonName) {
        if (commonName == null || commonName.isBlank()) {
            return EMPTY_COMMON_NAME_PLACEHOLDER;
        }
        return commonName;
    }

    public static X509Certificate getX509Certificate(byte[] decoded) throws CertificateException {
        try {
            X509Certificate certificate = (X509Certificate) new CertificateFactory().engineGenerateCertificate(new ByteArrayInputStream(decoded));
            if (certificate.getPublicKey() == null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Certificate has no public key, trying to generate certificate with BouncyCastleProvider: {}", Base64.getEncoder().encodeToString(decoded));
                }
                java.security.cert.CertificateFactory certificateFactory = java.security.cert.CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(decoded));
            }
            return certificate;
        } catch (Exception e) {
            throw new CertificateException("Failed to parse and create X509Certificate object from provided certificate content");
        }
    }

    public static X509Certificate getX509Certificate(String certInBase64) throws CertificateException {
        return getX509Certificate(Base64.getDecoder().decode(certInBase64));
    }

    public static X509Certificate getX509CertificateFromBase64Url(String certInBase64) throws CertificateException {
        return getX509Certificate(Base64.getUrlDecoder().decode(certInBase64));
    }

    public static String getBase64FromX509Certificate(X509Certificate certificate) throws CertificateException {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    public static int keyUsageExtractor(boolean[] keyUsage) {
        int result = 0;
        if (keyUsage != null) {
            for (int i = 0; i < keyUsage.length; i++) {
                if (keyUsage[i]) {
                    result |= (1 << i);  // set bit i
                }
            }
        }
        return result;
    }

    public static boolean isKeyUsagePresent(boolean[] keyUsage, CertificateKeyUsage keyUsageName) {
        if (keyUsage == null) {
            return false;
        }

        int keyUsageIndex = keyUsageName.getIndex();
        return keyUsageIndex >= 0 && keyUsageIndex < keyUsage.length && keyUsage[keyUsageIndex];
    }

    public static CertificateSubjectType getCertificateSubjectType(X509Certificate certificate, boolean subjectDnEqualsIssuerDn) {
        boolean selfSigned = false;
        if (subjectDnEqualsIssuerDn) {
            try {
                certificate.verify(certificate.getPublicKey());
                // Certificate is self-signed only if the signature of self has been successfully verified
                selfSigned = true;
            } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException |
                     SignatureException ignored) {
            }
        }

        int bcValue = certificate.getBasicConstraints();
        // Certificate is Certificate Authority if Basic Constraint Value is positive, otherwise it is End Entity
        if (bcValue >= 0) {
            return selfSigned ? CertificateSubjectType.ROOT_CA : CertificateSubjectType.INTERMEDIATE_CA;
        } else {
            return selfSigned ? CertificateSubjectType.SELF_SIGNED_END_ENTITY : CertificateSubjectType.END_ENTITY;
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, List<String>> getSAN(X509Certificate certificate) {
        Map<String, List<String>> sans = buildEmptySans();

        Collection<List<?>> encodedSans = null;
        try {
            encodedSans = certificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            logger.warn("Unable to get the SANs of the certificate");
            logger.warn(e.getMessage());
        }

        if (encodedSans == null) {
            return sans;
        }

        for (List<?> san : encodedSans) {
            String sanTypeName = null;
            try {
                Integer sanType = (Integer) san.get(0);
                sanTypeName = SAN_TYPE_MAP.get(sanType);
                String value = getSanValueString(sanType, san.get(1));
                ((ArrayList<String>) sans.get(sanTypeName)).add(value);
            } catch (Exception e) {
                logger.warn("Unable to get the SAN {} of the certificate", sanTypeName);
                logger.warn(e.getMessage());
            }
        }

        return sans;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, List<String>> getSAN(CertificateRequest certificateRequest) {
        Map<String, List<String>> sans = buildEmptySans();

        GeneralNames gns = null;

        if (certificateRequest instanceof Pkcs10CertificateRequest request) {
            Attribute[] certAttributes = request.getJcaObject().getAttributes();
            for (Attribute attribute : certAttributes) {
                if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                    Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
                    gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
                    break;
                }
            }
        } else if (certificateRequest instanceof CrmfCertificateRequest request) {
            Extensions extensions = Extensions.getInstance(request.getCertificateRequestMessage().getCertTemplate().getExtensions());
            gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        }

        if (gns == null) {
            return sans;
        }

        GeneralName[] names = gns.getNames();
        for (GeneralName name : names) {
            String sanTypeName = null;
            try {
                int sanType = name.getTagNo();
                sanTypeName = SAN_TYPE_MAP.get(sanType);
                String value = getSanValueString(sanType, sanType == GeneralName.otherName || sanType == GeneralName.ediPartyName ? name : name.getName());
                ((ArrayList<String>) sans.get(sanTypeName)).add(value);
            } catch (Exception e) {
                logger.warn("Unable to get the SAN {} of the certificate request", sanTypeName);
                logger.warn(e.getMessage());
            }
        }

        return sans;
    }

    private static String getSanValueString(Integer sanType, Object value) {
        if (sanType == GeneralName.otherName) {
            DLSequence otherNameSeq = (DLSequence) GeneralName.getInstance(value).getName();
            var oidSeq = otherNameSeq.getObjectAt(0).toString();
            var valueSeq = ((DLTaggedObject) otherNameSeq.getObjectAt(1)).getBaseObject().toString();
            return "%s=%s".formatted(oidSeq, valueSeq);
        }
        if (sanType == GeneralName.ediPartyName) {
            DLSequence ediPartySeq = (DLSequence) GeneralName.getInstance(value).getName();
            if (ediPartySeq.size() < 1 || ediPartySeq.size() > 2) {
                return value.toString();
            }
            return ediPartySeq.size() == 1 ? "Party=" + ediPartySeq.getObjectAt(0).toString()
                    : "Assigner=%s, Party=%s".formatted(ediPartySeq.getObjectAt(0).toString(), ediPartySeq.getObjectAt(1).toString());
        }

        return value.toString();
    }

    private static Map<String, List<String>> buildEmptySans() {
        return SAN_TYPE_MAP.values().stream().collect(Collectors.toMap(sanTypeName -> sanTypeName, sanTypeName -> new ArrayList<>(), (a, b) -> b));
    }

    public static X509Certificate parseUploadedCertificateContent(String certificateContent) {
        var decodedContent = Base64.getDecoder().decode(certificateContent);

        // check if certificate content is PEM encoded X.509 certificate
        boolean isPem = false;
        try (StringReader contentReader = new StringReader(new String(decodedContent));
             PEMParser pemParser = new PEMParser(contentReader)) {

            // alternative is to read straight with pemParser.readObject() and let to create object encoded in PEM by BouncyCastle
            // ideally creating own subclass of PEMParser to have the process under control
            PemObject pemObject = pemParser.readPemObject();

            // content contains PEM object
            if (pemObject != null) {
                logger.debug("PEM encoded certificate content uploaded. Type: {}", pemObject.getType());
                if (pemObject.getType().equals(PEMParser.TYPE_CERTIFICATE)
                        || pemObject.getType().equals(PEMParser.TYPE_X509_CERTIFICATE)
                        || pemObject.getType().equals(PEMParser.TYPE_PKCS7)) {
                    isPem = true;
                    decodedContent = pemObject.getContent();
                } else {
                    throw new ValidationException("Uploaded PEM encoded content is not certificate. Uploaded PEM type: " + pemObject.getType());
                }
            }
        } catch (IOException e) {
            logger.debug("Failed to parse uploaded certificate content as PEM encoded.");
        }

        // if not PEM is uploaded, check if it is not supported PKCS#12 format
        logger.debug("Binary certificate content uploaded");
        if (!isPem) {
            try (ByteArrayInputStream contentStream = new ByteArrayInputStream(decodedContent)) {
                KeyStore ks = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
                ks.load(contentStream, null);
            } catch (Exception e) {
                if (e.getMessage().equals("no password supplied when one expected")) {
                    throw new ValidationException("Unsupported certificate format PKCS#12");
                }
                logger.debug("Uploaded certificate is not PKCS12. Try parse content as binary X509Certificate");
            }
        }

        try {
            return getX509Certificate(decodedContent);
        } catch (CertificateException e) {
            logger.debug("Failed to parse content as binary X509Certificate: {}", e.getMessage());
            throw new ValidationException("Uploaded certificate content has invalid or unsupported format.");
        }
    }

    public static X509Certificate parseCertificate(String cert) throws CertificateException {
        cert = cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
                .replace("\r", "").replace("\n", "");
        byte[] decoded = Base64.getDecoder().decode(cert);
        return getX509Certificate(decoded);
    }

    public static String getThumbprint(byte[] encodedContent)
            throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(encodedContent);
        byte[] digest = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digest).toLowerCase();
    }

    public static String getSha1Thumbprint(byte[] encodedContent)
            throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        messageDigest.update(encodedContent);
        byte[] digest = messageDigest.digest();
        return DatatypeConverter.printHexBinary(digest).toLowerCase();
    }

    public static String getThumbprint(X509Certificate certificate)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        return getThumbprint(certificate.getEncoded());
    }

    public static String normalizeCertificateContent(String content) {
        return content
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\r", "")
                .replace("\n", "");
    }

    public static DiscoveryCertificate prepareDiscoveryCertificate(Certificate entry, X509Certificate certificate) {
        DiscoveryCertificate discoveryCertificate = new DiscoveryCertificate();
        if (entry != null) {
            discoveryCertificate.setCommonName(entry.getCommonName());
            discoveryCertificate.setSerialNumber(entry.getSerialNumber());
            discoveryCertificate.setIssuerCommonName(entry.getIssuerCommonName());
            discoveryCertificate.setNotAfter(entry.getNotAfter());
            discoveryCertificate.setNotBefore(entry.getNotBefore());
            discoveryCertificate.setCertificateContent(entry.getCertificateContent());
        } else {
            Certificate certificateModal = new Certificate();
            setSubjectDNParams(certificateModal, X500Name.getInstance(new PlatformX500NameStyle(false), certificate.getSubjectX500Principal().getEncoded()));
            setIssuerDNParams(certificateModal, X500Name.getInstance(new PlatformX500NameStyle(false), certificate.getIssuerX500Principal().getEncoded()));
            discoveryCertificate.setCommonName(certificateModal.getCommonName());
            discoveryCertificate.setIssuerCommonName(certificateModal.getIssuerCommonName());
            discoveryCertificate.setSerialNumber(certificate.getSerialNumber().toString(16));
            discoveryCertificate.setNotAfter(certificate.getNotAfter());
            discoveryCertificate.setNotBefore(certificate.getNotBefore());
        }

        return discoveryCertificate;
    }

    public static void prepareIssuedCertificate(Certificate modal, X509Certificate certificate) {
        stampIssuedFields(modal, certificate);
        modal.setState(CertificateState.ISSUED);
    }

    /**
     * Sets certificate data fields only; does NOT advance state. Callers routing
     * PENDING_ISSUE-&gt;ISSUED through {@link com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine}
     * call this before the SM transition; callers creating new certificate rows that bypass the SM
     * use {@link #prepareIssuedCertificate} instead.
     */
    public static void stampIssuedFields(Certificate modal, X509Certificate certificate) {
        modal.setComplianceStatus(ComplianceStatus.NOT_CHECKED);
        modal.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);

        modal.setSerialNumber(certificate.getSerialNumber().toString(16));
        modal.setNotAfter(certificate.getNotAfter());
        modal.setNotBefore(certificate.getNotBefore());
        if (certificate.getPublicKey() == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Invalid Certificate. Public Key is missing"
                    )
            );
        }
        try {
            modal.setPublicKeyFingerprint(getThumbprint(Base64.getEncoder().encodeToString(certificate.getPublicKey().getEncoded()).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to calculate the thumbprint of the certificate");
        }

        modal.setPublicKeyAlgorithm(getKeyAlgorithmStringFromProviderName(certificate.getPublicKey().getAlgorithm()));
        modal.setSignatureAlgorithm(certificate.getSigAlgName().replace("WITH", "with"));
        modal.setKeySize(KeySizeUtil.getKeyLength(certificate.getPublicKey()));
        modal.setCertificateType(CertificateType.fromCode(certificate.getType()));
        byte[] alternativeSignatureAlgorithm = certificate.getExtensionValue(Extension.altSignatureAlgorithm.getId());
        byte[] alternativeSignature = certificate.getExtensionValue(Extension.altSignatureValue.getId());
        if (alternativeSignatureAlgorithm != null && alternativeSignature != null) {
            try {
                modal.setAltSignatureAlgorithm(getAlternativeSignatureAlgorithm(alternativeSignatureAlgorithm).replace("WITH", "with"));
            } catch (IOException e) {
                logger.error("Cannot read Alternative Signature Algorithm from extension: {}", e.getMessage());
            }
        }

        modal.setSubjectAlternativeNames(CertificateUtil.serializeSans(CertificateUtil.getSAN(certificate)));

        byte[] subjectDnPrincipalEncoded = certificate.getSubjectX500Principal().getEncoded();
        byte[] issuerDnPrincipalEncoded = certificate.getIssuerX500Principal().getEncoded();
        setSubjectDNParams(modal, X500Name.getInstance(new PlatformX500NameStyle(false), subjectDnPrincipalEncoded));
        setIssuerDNParams(modal, X500Name.getInstance(new PlatformX500NameStyle(false), issuerDnPrincipalEncoded));
        modal.setIssuerDnNormalized(X500Name.getInstance(new PlatformX500NameStyle(true), issuerDnPrincipalEncoded).toString());
        modal.setSubjectDnNormalized(X500Name.getInstance(new PlatformX500NameStyle(true), subjectDnPrincipalEncoded).toString());
        CertificateSubjectType subjectType = CertificateUtil.getCertificateSubjectType(certificate, modal.getSubjectDnNormalized().equals(modal.getIssuerDnNormalized()));
        if (subjectType == CertificateSubjectType.ROOT_CA || subjectType == CertificateSubjectType.SELF_SIGNED_END_ENTITY) {
            modal.setIssuerSerialNumber(modal.getSerialNumber());
        }

        List<String> extendedKeyUsage = null;
        try {
            extendedKeyUsage = certificate.getExtendedKeyUsage();
        } catch (CertificateParsingException e) {
            logger.warn("Unable to get the extended key usage for certificate with serial number {} and subject DN {}: {}", modal.getSerialNumber(), modal.getSubjectDn(), e.getMessage());
        }
        if (extendedKeyUsage != null) {
            modal.setExtendedKeyUsage(MetaDefinitions.serializeArrayString(extendedKeyUsage));
            modal.setExtendedKeyUsageCritical(
                    certificate.getCriticalExtensionOIDs() != null
                            && certificate.getCriticalExtensionOIDs().contains(Extension.extendedKeyUsage.getId()));
        }

        QcStatementParseResult qc = null;
        try {
            qc = parseQcStatements(certificate);
        } catch (Exception e) {
            logger.warn("Unable to parse QCStatements extension for certificate with serial number {} and subject DN {}: {}", modal.getSerialNumber(), modal.getSubjectDn(), e.getMessage());
        }
        if (qc != null) {
            modal.setQcCompliance(qc.qcCompliance());
            modal.setQcSscd(qc.qcSscd());
            modal.setQcType(qc.qcType() != null
                    ? MetaDefinitions.serializeArrayString(
                    qc.qcType().stream().map(QcType::name).toList())
                    : null);
            modal.setQcCcLegislation(qc.qcCcLegislation() != null
                    ? MetaDefinitions.serializeArrayString(qc.qcCcLegislation())
                    : null);
        }

        modal.setKeyUsage(
                CertificateUtil.keyUsageExtractor(certificate.getKeyUsage()));
        modal.setSubjectType(subjectType);
        // Set trusted certificate mark either for CA or for self-signed certificate
        if (subjectType != CertificateSubjectType.END_ENTITY)
            modal.setTrustedCa(false);
    }

    /**
     * Parses the QCStatements extension (OID 1.3.6.1.5.5.7.1.3) of an X.509 certificate and extracts the four operationally
     * relevant statements per ETSI EN 319 412-5. Returns null when the extension is absent.
     */
    private static QcStatementParseResult parseQcStatements(X509Certificate cert) {
        byte[] raw = cert.getExtensionValue(Extension.qCStatements.getId());
        if (raw == null) return null;

        boolean qcCompliance = false;
        boolean qcSscd = false;
        List<QcType> qcType = new ArrayList<>();
        List<String> qcCcLegislation = new ArrayList<>();

        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1OctetString.getInstance(raw).getOctets());
        for (ASN1Encodable el : seq) {
            QCStatement stmt = QCStatement.getInstance(el);
            ASN1ObjectIdentifier id = stmt.getStatementId();

            if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.equals(id)) {
                qcCompliance = true;
            } else if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.equals(id)) {
                qcSscd = true;
            } else if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.equals(id)) {
                ASN1Sequence types = ASN1Sequence.getInstance(stmt.getStatementInfo());
                for (ASN1Encodable t : types) {
                    ASN1ObjectIdentifier typeOid = ASN1ObjectIdentifier.getInstance(t);
                    if (ETSIQCObjectIdentifiers.id_etsi_qct_esign.equals(typeOid)) qcType.add(QcType.ESIGN);
                    else if (ETSIQCObjectIdentifiers.id_etsi_qct_eseal.equals(typeOid)) qcType.add(QcType.ESEAL);
                    else if (ETSIQCObjectIdentifiers.id_etsi_qct_web.equals(typeOid)) qcType.add(QcType.WEB);
                }
            } else if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcCClegislation.equals(id)) {
                ASN1Sequence countries = ASN1Sequence.getInstance(stmt.getStatementInfo());
                for (ASN1Encodable cc : countries) {
                    qcCcLegislation.add(DERPrintableString.getInstance(cc).getString());
                }
            }
            // QcLimitValue, QcRetentionPeriod, QcPDS intentionally not parsed since they are not operationally relevant
        }

        return new QcStatementParseResult(qcCompliance, qcSscd,
                qcType.isEmpty() ? null : qcType,
                qcCcLegislation.isEmpty() ? null : qcCcLegislation);
    }

    record QcStatementParseResult(boolean qcCompliance,
                                  boolean qcSscd,
                                  List<QcType> qcType,
                                  List<String> qcCcLegislation) {
    }

    public static String getAlternativeSignatureAlgorithm(byte[] alternativeSignatureAlgorithm) throws IOException {
        ASN1Primitive derObj2 = getAsn1Primitive(alternativeSignatureAlgorithm);
        AltSignatureAlgorithm algorithm = AltSignatureAlgorithm.getInstance(derObj2);
        return new DefaultAlgorithmNameFinder().getAlgorithmName(algorithm.getAlgorithm());
    }

    public static byte[] getAltSignatureValue(byte[] altSignatureValue) throws IOException {
        ASN1Primitive primitive = getAsn1Primitive(altSignatureValue);
        AltSignatureValue signatureValue = AltSignatureValue.getInstance(primitive);
        return signatureValue.getSignature().getEncoded();
    }

    public static PublicKey getAltPublicKey(byte[] altPublicKeyInfoEncoded) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ASN1Primitive primitive = getAsn1Primitive(altPublicKeyInfoEncoded);
        SubjectAltPublicKeyInfo subjectAltPublicKeyInfo = SubjectAltPublicKeyInfo.getInstance(primitive);
        KeyFactory keyFactory = KeyFactory.getInstance(subjectAltPublicKeyInfo.getAlgorithm().getAlgorithm().getId());
        return keyFactory.generatePublic(new X509EncodedKeySpec(subjectAltPublicKeyInfo.getEncoded()));
    }


    private static ASN1Primitive getAsn1Primitive(byte[] encodedAsn1Primitive) throws IOException {
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(encodedAsn1Primitive));
        ASN1Primitive asn1Primitive = asn1InputStream.readObject();
        DEROctetString derOctetString = (DEROctetString) asn1Primitive;

        asn1InputStream.close();

        byte[] octets = derOctetString.getOctets();
        ASN1InputStream asn1InputStreamInner = new ASN1InputStream(new ByteArrayInputStream(octets));
        return asn1InputStreamInner.readObject();
    }


    public static void prepareCsrObject(Certificate modal, CertificateRequest certificateRequest) throws NoSuchAlgorithmException, CertificateRequestException {
        if (certificateRequest.getPublicKey() == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Invalid public key in certificate request"
                    )
            );
        }
        setSubjectDNParams(modal, X500Name.getInstance(new PlatformX500NameStyle(false), certificateRequest.getSubject()));
        try {
            modal.setPublicKeyFingerprint(getThumbprint(Base64.getEncoder().encodeToString(certificateRequest.getPublicKey().getEncoded()).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to get the thumbprint of the certificate request: {}", e.getMessage());
        }
        if (getKeyAlgorithmEnumFromProviderName(certificateRequest.getPublicKey().getAlgorithm()) != null) {
            modal.setPublicKeyAlgorithm(getKeyAlgorithmStringFromProviderName(certificateRequest.getPublicKey().getAlgorithm()));
        }
        modal.setKeySize(KeySizeUtil.getKeyLength(certificateRequest.getPublicKey()));
        modal.setSubjectAlternativeNames(CertificateUtil.serializeSans(certificateRequest.getSubjectAlternativeNames()));
    }

    private static void setIssuerDNParams(Certificate modal, X500Name issuerDN) {
        modal.setIssuerDn(issuerDN.toString());

        for (RDN i : issuerDN.getRDNs()) {
            if (i.getFirst() == null) continue;

            if (SystemOid.COMMON_NAME.getOid().equals(i.getFirst().getType().getId())) {
                modal.setIssuerCommonName(i.getFirst().getValue().toString());
            }
        }
    }

    /**
     * Records the subject identity of a no-CSR registration placeholder from the operator-supplied
     * subject DN. Sets the subject DN and common name only; key, SAN and fingerprint fields stay
     * empty until issuance fills them. A blank DN is a no-op (subject carried entirely in the SAN,
     * permitted by RFC 5280 §4.1.2.6).
     */
    public static void applyRegistrationSubject(Certificate modal, String subjectDn) {
        if (subjectDn == null || subjectDn.isBlank()) {
            return;
        }
        try {
            setSubjectDNParams(modal, new X500Name(new PlatformX500NameStyle(false), subjectDn));
        } catch (IllegalArgumentException e) {
            throw new ValidationException(ValidationError.create("Invalid subject DN '%s': %s".formatted(subjectDn, e.getMessage())));
        }
    }

    private static void setSubjectDNParams(Certificate modal, X500Name subjectDN) {
        modal.setSubjectDn(subjectDN.toString());

        for (RDN i : subjectDN.getRDNs()) {
            if (i.getFirst() == null) continue;

            if (SystemOid.COMMON_NAME.getOid().equals(i.getFirst().getType().getId())) {
                modal.setCommonName(i.getFirst().getValue().toString());
            }
        }
    }

    public static KeyAlgorithm getKeyAlgorithmEnumFromProviderName(String providerName) {
        if (providerName == null) return null;
        KeyAlgorithm keyAlgorithm = CERTIFICATE_ALGORITHM_FROM_PROVIDER.get(providerName);
        if (keyAlgorithm != null) return keyAlgorithm;
        if (providerName.contains("ML-DSA")) return KeyAlgorithm.MLDSA;
        if (providerName.contains("SLH-DSA")) return KeyAlgorithm.SLHDSA;
        return KeyAlgorithm.UNKNOWN;
    }

    public static String getKeyAlgorithmStringFromProviderName(String providerName) {
        KeyAlgorithm keyAlgorithm = getKeyAlgorithmEnumFromProviderName(providerName);
        if (keyAlgorithm == KeyAlgorithm.UNKNOWN || keyAlgorithm == null) return providerName;
        return keyAlgorithm.getCode();
    }

    @Deprecated(forRemoval = true)
    /**
     * @deprecated Used only in a past migration
     */
    public static String getAlgorithmFromProviderName(String providerName) {
        return null;
    }

    public static List<JcaX509CertificateHolder> convertToX509CertificateHolder(List<X509Certificate> certificateChain) throws CertificateEncodingException {
        List<JcaX509CertificateHolder> certificateHolderChain = new ArrayList<>();
        for (X509Certificate certificate : certificateChain) {
            certificateHolderChain.add(new JcaX509CertificateHolder(certificate));
        }
        return certificateHolderChain;
    }

    /**
     * Function to convert: from list of X509 certificates to list of CMPCertificates
     *
     * @param certs certificates to convert
     * @return array of converted certificates
     * @throws CertificateException if certificate could not be converted
     */
    public static CMPCertificate[] toCmpCertificates(List<X509Certificate> certs) throws CertificateException {
        CMPCertificate[] cmpCertificates = new CMPCertificate[certs.size()];
        int index = 0;
        for (X509Certificate x509Cert : certs) {
            cmpCertificates[index++] = toCmpCertificate(x509Cert);
        }
        return cmpCertificates;
    }

    /**
     * Function to convert: from single X509 certificate to CMPCertificate
     *
     * @param cert certificate to convert
     * @return converted certificate
     * @throws CertificateException if certificate could not be converted
     */
    public static CMPCertificate toCmpCertificate(final java.security.cert.Certificate cert)
            throws CertificateException {
        return CMPCertificate.getInstance(cert.getEncoded());
    }

    /**
     * Checks whether given X.509 certificate is intermediate certificate and not
     * self-signed.
     *
     * @param cert certificate to be checked
     * @return <code>true</code> if the certificate is intermediate and not
     * self-signed
     */
    public static boolean isIntermediateCertificate(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());// true=self-signed (certificate signature with its own public key)
            return false;
        } catch (final SignatureException | InvalidKeyException keyEx) {
            return true;// invalid key == it is not self-signed
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            return false;// could be self-signed
        }
    }

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static byte[] generateRandomBytes(int length) {
        final byte[] generated = new byte[length];
        SECURE_RANDOM.nextBytes(generated);
        return generated;
    }

    /**
     * Serialize the subject alternative names to a string
     *
     * @param subjectAlternativeNames the subject alternative names
     * @return the serialized string
     */
    public static String serializeSans(Map<String, List<String>> subjectAlternativeNames) {
        if (subjectAlternativeNames == null) {
            return "{}";
        }
        // Check for null values in the map
        for (Map.Entry<String, List<String>> entry : subjectAlternativeNames.entrySet()) {
            if (entry.getValue() == null) {
                throw new IllegalStateException("SAN list contains a null value for key: " + entry.getKey());
            }
        }
        try {
            return OBJECT_MAPPER.writeValueAsString(subjectAlternativeNames);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize SANs", e);
        }
    }

    /**
     * Deserialize the subject alternative names from a string
     *
     * @param subjectAlternativeNames the serialized string
     * @return the deserialized map
     */
    public static Map<String, List<String>> deserializeSans(String subjectAlternativeNames) {
        if (subjectAlternativeNames == null || subjectAlternativeNames.isEmpty()) {
            return new HashMap<>();
        }
        try {
            JsonNode jsonNode = OBJECT_MAPPER.readTree(subjectAlternativeNames);
            return OBJECT_MAPPER.convertValue(jsonNode, new TypeReference<>() {
            });
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to deserialize SANs", e);
        }
    }

    public static boolean isValidationEnabled(Certificate certificate, @Nullable CertificateValidationResultDto validationResultDto) {
        if (certificate.isArchived()) return false;
        Boolean raValidationEnabled = certificate.getRaProfile() != null ? certificate.getRaProfile().getValidationEnabled() : null;

        if (Boolean.FALSE.equals(raValidationEnabled)) {
            certificate.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
            if (validationResultDto != null) {
                validationResultDto.setMessage("Validation of certificates in RA Profile %s is disabled."
                        .formatted(certificate.getRaProfile().getName()));
            }
            return false;
        } else if (raValidationEnabled == null) {
            PlatformSettingsDto platformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
            CertificateValidationSettingsDto validationSettings = platformSettings.getCertificates().getValidation();

            if (Boolean.FALSE.equals(validationSettings.getEnabled())) {
                certificate.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
                if (validationResultDto != null) {
                    validationResultDto.setMessage("Validation of certificates is disabled in platform settings.");
                }
                return false;
            } else return certificate.getCertificateContent() != null;
        } else return certificate.getCertificateContent() != null;
    }

}
