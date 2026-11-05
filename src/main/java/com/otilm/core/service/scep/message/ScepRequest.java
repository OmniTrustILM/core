package com.otilm.core.service.scep.message;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.api.model.core.scep.MessageType;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.SignatureVerificationBounds;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.PasswordRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses a signed SCEP request and opens its envelope before exposing the request payload.
 */
public class ScepRequest {

    private static final Logger logger = LoggerFactory.getLogger(ScepRequest.class);

    /**
     * The most PBKDF2 iterations that a password recipient may state. Its key is derived from the challenge password
     * before the client is authenticated, so this bounds what one request costs: the same protocol-hardening bound as
     * for the password-based MAC of CMP, not an operator setting.
     */
    static final int MAX_PBKDF2_ITERATION_COUNT = 100_000;

    /**
     * The algorithms that the content of a request may be encrypted with: AES and DES3, which GetCACaps advertises. RFC
     * 8894 forbids single DES. BouncyCastle also accepts a password-based algorithm here, such as a PKCS#12 one, and
     * derives its key over the iteration count that the client states once the content key is unwrapped, which for a CA
     * key that is RSA needs nothing but the CA certificate.
     */
    private static final Set<ASN1ObjectIdentifier> CONTENT_ENCRYPTION_ALGORITHMS = Set
            .of(CMSAlgorithm.AES128_CBC, CMSAlgorithm.AES192_CBC, CMSAlgorithm.AES256_CBC, CMSAlgorithm.DES_EDE3_CBC);

    private final byte[] message;
    private String digestAlgorithmOid;
    private SignedData signedData;
    private byte[] requestKeyInfo;
    private MessageType messageType;
    private String transactionId;
    private String senderNonce;
    private ContentInfo encapsulatedContent;
    private EnvelopedData envelopedData;
    private JcaPKCS10CertificationRequest pkcs10Request;
    private X509Certificate signerCertificate;

    /**
     * Content encryption algorithm This value should be set based on the data from the SCEP request message If there is
     * a problem identifying the encryption algorithm, the error will be thrown out but to be on the safer side, the
     * default value is added
     */
    private ASN1ObjectIdentifier contentEncryptionAlgorithm = SMIMECapability.dES_EDE3_CBC;

    public ScepRequest(byte[] message) throws ScepException {
        this.message = message;
        readMessage();
    }

    public String getDigestAlgorithmOid() {
        return digestAlgorithmOid;
    }

    public byte[] getRequestKeyInfo() {
        return requestKeyInfo;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public String getSenderNonce() {
        return senderNonce;
    }

    public ContentInfo getEncapsulatedContent() {
        return encapsulatedContent;
    }

    public EnvelopedData getEnvelopedData() {
        return envelopedData;
    }

    public X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    public JcaPKCS10CertificationRequest getPkcs10Request() {
        return pkcs10Request;
    }

    public ASN1ObjectIdentifier getContentEncryptionAlgorithm() {
        return contentEncryptionAlgorithm;
    }

    private void readMessage() throws ScepException {
        try {
            readDigestAlgorithm();
        } catch (CMSException e) {
            String errorMessage = "Exception trying to identify digest algorithm";
            logger.error(errorMessage + ": ", e);
            throw new ScepException(errorMessage, e, FailInfo.BAD_MESSAGE_CHECK);
        }

        try {
            checkContentType();
        } catch (IOException e) {
            String errorMessage = "Exception trying to check content type";
            logger.error(errorMessage + ": ", e);
            throw new ScepException(errorMessage, e, FailInfo.BAD_MESSAGE_CHECK);
        }

        readAttributes();

        try {
            readRequestKeyInfo();
        } catch (IOException e) {
            String errorMessage = "Exception trying to read request key info (certificate)";
            logger.error(errorMessage + ": ", e);
            throw new ScepException(errorMessage, e, FailInfo.BAD_REQUEST);
        }

        try {
            readRequest();
        } catch (IOException e) {
            String errorMessage = "Exception trying to read request content";
            logger.error(errorMessage + ": ", e);
            throw new ScepException(errorMessage, e, FailInfo.BAD_REQUEST);
        }

        readContentEncryptionAlgorithm();
    }

    private void readDigestAlgorithm() throws CMSException, ScepException {
        CMSSignedData cmsSignedData = new CMSSignedData(message);
        SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> signerInformation = signerInformationStore.getSigners();
        signerInformation.forEach(signerInformationElement -> {
            digestAlgorithmOid = signerInformationElement.getDigestAlgOID();
            logger.debug("Identified digest algorithm: " + digestAlgorithmOid);
        });
        readSignerCertificate(cmsSignedData);
    }

    private void readSignerCertificate(CMSSignedData cmsSignedData) throws ScepException {
        Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
        SignerInformationStore signerInfos = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> signers = signerInfos.getSigners();
        List<X509Certificate> certificates = new ArrayList<>();
        boolean skippedForItsKey = false;
        for (SignerInformation signer : signers) {
            try {
                Collection<X509CertificateHolder> matches = certStore.getMatches(signer.getSID());
                for (X509CertificateHolder holder : matches) {
                    if (hasSupportedKey(holder)) {
                        certificates.add(new JcaX509CertificateConverter().getCertificate(holder));
                    } else {
                        skippedForItsKey = true;
                    }
                }
            } catch (java.security.cert.CertificateException e) {
                logger.error(e.getMessage());
            }
        }
        if (certificates.isEmpty()) {
            if (skippedForItsKey) {
                throw new ScepException("The key of the signer certificate is not supported", FailInfo.BAD_ALG);
            }
            throw new ScepException("No Signer Information available on the request");
        }
        this.signerCertificate = certificates.get(0);
    }

    /**
     * Converting a certificate builds its key, of whatever algorithm the client chose, so a certificate whose key is
     * beyond the bounds is skipped before it is converted.
     */
    private static boolean hasSupportedKey(X509CertificateHolder certificate) {
        try {
            SignatureVerificationBounds.requireSupportedPublicKey(certificate.getSubjectPublicKeyInfo());
            return true;
        } catch (InvalidKeyException e) {
            logger.debug("Skipping a signer certificate of the SCEP request: {}", e.getMessage());
            return false;
        }
    }

    private void checkContentType() throws IOException, ScepException {
        ContentInfo contentInfo = readContentInfo(new ByteArrayInputStream(message));
        String contentType = contentInfo.getContentType().getId();
        if (!contentType.equals(CMSObjectIdentifiers.signedData.getId())) {
            throw new ScepException("Content type is not signedData", FailInfo.BAD_MESSAGE_CHECK);
        } else {
            signedData = SignedData.getInstance(ASN1Sequence.getInstance(contentInfo.getContent()));
        }
    }

    private void readContentEncryptionAlgorithm() throws ScepException {
        try {
            CMSEnvelopedData cmsEnvelopedData = new CMSEnvelopedData(encapsulatedContent.getEncoded());
            this.contentEncryptionAlgorithm = cmsEnvelopedData.getContentEncryptionAlgorithm().getAlgorithm();
        } catch (IOException | CMSException e) {
            String errorMessage = "Exception trying to read content encryption algorithm";
            logger.error(errorMessage + ": ", e);
            throw new ScepException(errorMessage, e, FailInfo.BAD_REQUEST);
        }
    }

    private void readAttributes() {
        Enumeration<?> signerInfos = signedData.getSignerInfos().getObjects();

        signerInfos.asIterator().forEachRemaining(signerInfoElement -> {
            SignerInfo signerInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfoElement));
            Enumeration<?> authenticatedAttributes = signerInfo.getAuthenticatedAttributes().getObjects();

            authenticatedAttributes.asIterator().forEachRemaining(attributeElement -> {
                Attribute attribute = Attribute.getInstance(ASN1Sequence.getInstance(attributeElement));
                String attributeOid = attribute.getAttrType().getId();
                logger.debug("SignerInfo Attribute: " + attributeOid);

                // According to SCEP RFC, all the attributes are represented by the string format of the integer.
                // Check if the attribute oid is of the specified type and if it is, then get the constant from
                // the enum
                if (attributeOid.equals(ScepConstants.id_messageType)) {
                    Enumeration<?> attributeValues = attribute.getAttrValues().getObjects();
                    ASN1PrintableString asn1PrintableString = ASN1PrintableString
                            .getInstance(attributeValues.nextElement());
                    messageType = MessageType.resolve(Integer.parseInt(asn1PrintableString.getString()));
                }

                if (attributeOid.equals(ScepConstants.id_transactionId)) {
                    Enumeration<?> attributeValues = attribute.getAttrValues().getObjects();
                    ASN1PrintableString asn1PrintableString = ASN1PrintableString
                            .getInstance(attributeValues.nextElement());
                    transactionId = asn1PrintableString.getString();
                }

                if (attributeOid.equals(ScepConstants.id_senderNonce)) {
                    Enumeration<?> attributeValues = attribute.getAttrValues().getObjects();
                    ASN1OctetString asn1OctetString = ASN1OctetString.getInstance(attributeValues.nextElement());
                    senderNonce = Base64.getEncoder().encodeToString(asn1OctetString.getOctets());
                }

            });
        });
    }

    private void readRequestKeyInfo() throws IOException {
        ASN1Set certificates = signedData.getCertificates();
        if (certificates.size() > 0) { // there should be one certificate
            ASN1Encodable asn1Certificate = certificates.getObjectAt(0);
            if (asn1Certificate != null) {
                final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                final ASN1OutputStream asn1OutputStream = ASN1OutputStream
                        .create(byteArrayOutputStream, ASN1Encoding.DER);
                asn1OutputStream.writeObject(asn1Certificate);
                if (byteArrayOutputStream.size() > 0) {
                    requestKeyInfo = byteArrayOutputStream.toByteArray();
                }
            }
        }
    }

    private void readRequest() throws ScepException, IOException {
        if (!messageType.equals(MessageType.PKCS_REQ) && !messageType.equals(MessageType.RENEWAL_REQ)
                && !messageType.equals(MessageType.CERT_POLL)) {
            throw new ScepException("Wrong type of message: " + messageType, FailInfo.BAD_REQUEST);
        }

        ContentInfo encapsulatedContentInfo = signedData.getEncapContentInfo();
        String contentTypeOid = encapsulatedContentInfo.getContentType().getId();

        if (!contentTypeOid.equals(CMSObjectIdentifiers.data.getId())) {
            throw new ScepException("EncapsulatedContentInfo does not contain data content type", FailInfo.BAD_REQUEST);
        } else {
            final ASN1OctetString asn1EncapsulatedContent = ASN1OctetString
                    .getInstance(encapsulatedContentInfo.getContent());
            encapsulatedContent = readContentInfo(new ByteArrayInputStream(asn1EncapsulatedContent.getOctets()));

            String encapsulatedContentInfoOid = encapsulatedContent.getContentType().getId();

            if (!encapsulatedContentInfoOid.equals(CMSObjectIdentifiers.envelopedData.getId())) {
                throw new ScepException("EncapsulatedContentInfo does not contain PKCS7 envelopedData",
                        FailInfo.BAD_REQUEST);
            } else {
                envelopedData = EnvelopedData.getInstance(ASN1Sequence.getInstance(encapsulatedContent.getContent()));
            }
        }
    }

    private ContentInfo readContentInfo(InputStream inputStream) throws IOException {
        final ASN1InputStream asn1InputStream = new ASN1InputStream(inputStream);
        ASN1Sequence asn1Sequence;
        try {
            asn1Sequence = ASN1Sequence.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        return ContentInfo.getInstance(asn1Sequence);
    }

    public void decryptData(PlatformPrivateKey privateKey, Provider provider, KeyAlgorithm keyAlgorithm,
            String challengePassword) throws ScepException, CMSException {
        CMSEnvelopedData cmsEnvelopedData;
        try {
            cmsEnvelopedData = new CMSEnvelopedData(encapsulatedContent.getEncoded());
        } catch (IOException | CMSException e) {
            String errorMessage = "Failed to decode encapsulated content";
            logger.error(errorMessage + ": ", e);
            throw new ScepException(errorMessage, e, FailInfo.BAD_REQUEST);
        }
        if (!CONTENT_ENCRYPTION_ALGORITHMS.contains(cmsEnvelopedData.getContentEncryptionAlgorithm().getAlgorithm())) {
            throw new ScepException("The content of the request is encrypted with an algorithm that is not supported",
                    FailInfo.BAD_ALG);
        }
        RecipientInformationStore recipientInfos = cmsEnvelopedData.getRecipientInfos();
        Collection<RecipientInformation> recipients = recipientInfos.getRecipients();
        Iterator<RecipientInformation> recipientInformationIterator = recipients.iterator();
        byte[] decryptedData = null;

        if (recipientInformationIterator.hasNext()) {
            RecipientInformation recipient = recipientInformationIterator.next();
            if (keyAlgorithm.equals(KeyAlgorithm.RSA)) {
                if (privateKey == null || provider == null) {
                    throw new ScepException("Private key or provider is null", FailInfo.BAD_REQUEST);
                }
                JceKeyTransEnvelopedRecipient jceKeyTransEnvelopedRecipient = new JceKeyTransEnvelopedRecipient(
                        privateKey);
                jceKeyTransEnvelopedRecipient.setProvider(provider);
                jceKeyTransEnvelopedRecipient.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
                jceKeyTransEnvelopedRecipient.setMustProduceEncodableUnwrappedKey(true);

                try {
                    decryptedData = recipient.getContent(jceKeyTransEnvelopedRecipient);
                } catch (CMSException | ProviderException e) {
                    String errorMessage = "Failed to decrypt encapsulated content";
                    logger.error(errorMessage + ": ", e);
                    throw new ScepException(errorMessage, e, FailInfo.BAD_REQUEST);
                }
            } else {
                // A non-key-transport CA key can only unwrap the RFC 8894 password recipient, which needs
                // the shared challenge password: without one the request is undecryptable, not malformed.
                if (challengePassword == null || challengePassword.isEmpty()) {
                    throw new ScepException("A challenge password must be configured on the SCEP profile to decrypt "
                            + "requests enveloped to a non-RSA CA key", FailInfo.BAD_ALG);
                }
                requireBoundedPasswordRecipient(recipient);
                JcePasswordEnvelopedRecipient jcePasswordEnvelopedRecipient = new JcePasswordEnvelopedRecipient(
                        challengePassword.toCharArray());
                jcePasswordEnvelopedRecipient.setProvider(BouncyCastleProvider.PROVIDER_NAME);
                decryptedData = recipient.getContent(jcePasswordEnvelopedRecipient);
            }
        }
        // A bare assert is a no-op in production: an EnvelopedData carrying no recipientInfo would skip the
        // block above and reach the PKCS#10 parse with no content.
        if (decryptedData == null) {
            throw new ScepException("The SCEP request contains no recipient information to decrypt",
                    FailInfo.BAD_REQUEST);
        }
        try {
            if (messageType.equals(MessageType.PKCS_REQ) || messageType.equals(MessageType.RENEWAL_REQ)) {
                JcaPKCS10CertificationRequest request = new JcaPKCS10CertificationRequest(decryptedData);
                requireBoundedRequest(request);
                pkcs10Request = request;
            }
        } catch (IOException e) {
            String errorMessage = "Failed to load decrypted PKCS#10 request";
            logger.error(errorMessage + ": ", e);
            throw new ScepException(errorMessage, e, FailInfo.BAD_REQUEST);
        }
    }

    /**
     * A CA key that is not RSA opens only a password recipient. BouncyCastle derives the key of one as PBKDF2 over the
     * parameters that the client states, whatever key derivation algorithm it names, and admits up to 10,000,000
     * iterations unless the JVM-wide {@code org.bouncycastle.pbe.max_iteration_count} says otherwise. Only PBKDF2 over
     * at most {@value #MAX_PBKDF2_ITERATION_COUNT} iterations is derived here.
     */
    private static void requireBoundedPasswordRecipient(RecipientInformation recipient) throws ScepException {
        if (!(recipient instanceof PasswordRecipientInformation passwordRecipient)) {
            throw new ScepException("A request enveloped to a CA key that is not RSA must use a password recipient",
                    FailInfo.BAD_ALG);
        }
        BigInteger iterationCount = pbkdf2IterationCount(passwordRecipient.getKeyDerivationAlgorithm())
                .orElseThrow(() -> new ScepException(
                        "The password recipient states a key derivation that is not supported", FailInfo.BAD_ALG));
        if (iterationCount.signum() <= 0
                || iterationCount.compareTo(BigInteger.valueOf(MAX_PBKDF2_ITERATION_COUNT)) > 0) {
            throw new ScepException("The PBKDF2 iteration count of the password recipient is not between 1 and %d"
                    .formatted(MAX_PBKDF2_ITERATION_COUNT), FailInfo.BAD_ALG);
        }
    }

    /** The PBKDF2 iteration count that a key derivation states; empty when it is absent, not PBKDF2 or unreadable. */
    private static Optional<BigInteger> pbkdf2IterationCount(AlgorithmIdentifier keyDerivation) {
        if (keyDerivation == null || !PKCSObjectIdentifiers.id_PBKDF2.equals(keyDerivation.getAlgorithm())) {
            return Optional.empty();
        }
        try {
            return Optional.of(PBKDF2Params.getInstance(keyDerivation.getParameters()).getIterationCount());
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /**
     * The proof of possession verifies the signature of the request with its public key, and enrolment builds its
     * public keys, both possibly before the client is authenticated, so a request beyond the bounds is refused here.
     */
    private static void requireBoundedRequest(JcaPKCS10CertificationRequest request) throws ScepException {
        try {
            SignatureVerificationBounds.requireBoundedRequest(request);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new ScepException("The PKCS#10 request uses a key or a signature algorithm that is not supported", e,
                    FailInfo.BAD_ALG);
        }
    }

    // TODO: this method should have own implementation in PKCS#10 request, as it is general for all such requests, not
    // only SCEP
    public String getChallengePassword() {
        // Try to get the challenge password using the direct challenge password extemsion
        org.bouncycastle.asn1.pkcs.Attribute[] attributes = this.pkcs10Request
                .getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
        // If there are no values, there is a possibility that its inside the CSR extensions.
        // Iterate and gather the value from the CSR extension
        if (attributes.length == 0) {
            attributes = this.getPkcs10Request().getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (attributes.length == 0) {
                return null;
            }

            ASN1Set asn1Encodables = attributes[0].getAttrValues();
            if (asn1Encodables.size() == 0) {
                return null;
            }

            Extensions exts = Extensions.getInstance(asn1Encodables.getObjectAt(0));
            Extension ext = exts.getExtension(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
            if (ext == null) {
                return null;
            }
            return extractPasswordFromAsn1(ext.getExtnValue());
        } else {
            return extractPasswordFromAsn1(attributes[0].getAttrValues().getObjectAt(0));
        }
    }

    private String extractPasswordFromAsn1(Object extnValue) {
        if (extnValue == null) {
            return null;
        }
        Object challengePassword;
        try {
            challengePassword = DirectoryString.getInstance(extnValue);
        } catch (IllegalArgumentException e) {
            challengePassword = DERIA5String.getInstance(extnValue);
        }
        if (challengePassword != null) {
            return ((ASN1String) challengePassword).getString();
        }
        return "";
    }

    // TODO: this method should have own implementation in PKCS#10 request, as it is general for all such requests, not
    // only SCEP
    public boolean verifyRequest()
            throws NoSuchAlgorithmException, InvalidKeySpecException, PKCSException, OperatorCreationException {
        if (pkcs10Request == null) {
            return false;
        }
        PublicKey publicKey = CryptographyUtil.decodePublicKey(pkcs10Request.getSubjectPublicKeyInfo());
        ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(publicKey);
        return pkcs10Request.isSignatureValid(contentVerifierProvider);
    }

    public boolean verifySignature(PublicKey publicKey)
            throws CMSException, OperatorCreationException, InvalidAlgorithmParameterException {
        CMSSignedData cmsSignedData = new CMSSignedData(message);
        for (SignerInformation signer : cmsSignedData.getSignerInfos().getSigners()) {
            SignatureVerificationBounds
                    .requireBoundedSignatureAlgorithm(signer.toASN1Structure().getDigestEncryptionAlgorithm());
        }
        // SCEP defines no countersignatures, and BouncyCastle would verify each one with the algorithm that it states
        return cmsSignedData.verifySignatures(new ScepVerifierProvider(publicKey), true);
    }

}
