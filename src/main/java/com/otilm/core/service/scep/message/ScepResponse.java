package com.otilm.core.service.scep.message;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.api.model.core.scep.MessageType;
import com.otilm.api.model.core.scep.PkiStatus;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.util.AlgorithmUtil;
import com.otilm.core.util.CertificateUtil;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Hashtable;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScepResponse {

    private static final Logger logger = LoggerFactory.getLogger(ScepResponse.class);

    private PkiStatus pkiStatus;
    private FailInfo failInfo;
    private String failInfoText;
    private String recipientNonce;
    private String senderNonce;
    private String transactionId;
    private Certificate caCertificate;
    private List<X509Certificate> certificateChain;
    private byte[] recipientKeyInfo;
    private String digestAlgorithmOid;
    private char[] challengePassword;

    private CMSTypedData responseData;

    private CMSSignedData signedResponseData;

    /**
     * The certificate to sign the response with.
     */
    private X509Certificate signerCertificate;
    /**
     * The private key to sign the response.
     */
    private PlatformPrivateKey signerPrivateKey;
    /**
     * The provider to use for signing the response.
     */
    private Provider signerProvider;

    /**
     * Content encryption algorithm This value should be set based on the data from the SCEP request message If there is
     * a problem identifying the encryption algorithm, the error will be thrown out but to be on the safer side, the
     * default value is added
     */
    private ASN1ObjectIdentifier contentEncryptionAlgorithm = SMIMECapability.dES_EDE3_CBC;

    public ScepResponse() {
    }

    public void setFailInfo(FailInfo failInfo) {
        this.failInfo = failInfo;
    }

    public void setPkiStatus(PkiStatus pkiStatus) {
        this.pkiStatus = pkiStatus;
    }

    public void setFailInfoText(String failInfoText) {
        this.failInfoText = failInfoText;
    }

    public void setRecipientNonce(String recipientNonce) {
        this.recipientNonce = recipientNonce;
    }

    public void setSenderNonce(String senderNonce) {
        this.senderNonce = senderNonce;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public void setCaCertificate(Certificate caCertificate) {
        this.caCertificate = caCertificate;
    }

    public void setCertificateChain(List<X509Certificate> certificateChain) {
        this.certificateChain = certificateChain;
    }

    public void setRecipientKeyInfo(byte[] recipientKeyInfo) {
        this.recipientKeyInfo = recipientKeyInfo;
    }

    public void setDigestAlgorithmOid(String digestAlgorithmOid) {
        this.digestAlgorithmOid = digestAlgorithmOid;
    }

    /**
     * The shared SCEP challenge password, used to envelope the SUCCESS response when the recipient key cannot receive
     * an RSA-key-transport envelope (e.g. an EC client key).
     */
    public void setChallengePassword(String challengePassword) {
        this.challengePassword = challengePassword != null ? challengePassword.toCharArray() : null;
    }

    public PkiStatus getPkiStatus() {
        return pkiStatus;
    }

    public CMSSignedData getSignedResponseData() {
        return signedResponseData;
    }

    public ASN1ObjectIdentifier getContentEncryptionAlgorithm() {
        return contentEncryptionAlgorithm;
    }

    public void setContentEncryptionAlgorithm(ASN1ObjectIdentifier contentEncryptionAlgorithm) {
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
    }

    public void setSigningAttributes(X509Certificate signerCertificate, PlatformPrivateKey signerPrivateKey,
            Provider signerProvider) {
        this.signerCertificate = signerCertificate;
        this.signerPrivateKey = signerPrivateKey;
        this.signerProvider = signerProvider;
    }

    public void generate() throws ScepException {
        // Create the response data
        try {
            createResponseData();
        } catch (CertificateException | CMSException | IOException e) {
            String errorMessage = "Exception creating CMS message as response data";
            logger.error(errorMessage + ": ", e);
            throw new ScepException(errorMessage, e, FailInfo.BAD_REQUEST);
        }

        // Sign the response data
        try {
            createSignedData();
        } catch (CertificateEncodingException | NoSuchAlgorithmException | OperatorCreationException | CMSException e) {
            String errorMessage = "Exception signing CMS response data";
            logger.error(errorMessage + ": ", e);
            throw new ScepException(errorMessage, e, FailInfo.BAD_REQUEST);
        }
    }

    private void createResponseData() throws CertificateException, CMSException, IOException {
        if (pkiStatus.equals(PkiStatus.SUCCESS)) {
            responseData = new CMSProcessableByteArray(buildEnvelopedResponse().getEncoded());
        } else {
            responseData = new CMSProcessableByteArray(new byte[0]);
        }
    }

    CMSEnvelopedData buildEnvelopedResponse() throws CertificateException, CMSException, IOException {
        CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
        cmsSignedDataGenerator
                .addCertificates(
                        new CollectionStore<>(CertificateUtil.convertToX509CertificateHolder(certificateChain)));
        CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(new CMSAbsentContent(), false);

        X509Certificate recipient = recipientKeyInfo != null
                ? CertificateUtil.getX509Certificate(recipientKeyInfo)
                : certificateChain.get(0);

        CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
        cmsEnvelopedDataGenerator.addRecipientInfoGenerator(buildRecipientInfoGenerator(recipient));

        // Take the content encryption algorithm from the response that is set from the SCEP request message
        JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(
                contentEncryptionAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return cmsEnvelopedDataGenerator
                .generate(new CMSProcessableByteArray(cmsSignedData.getEncoded()),
                        jceCMSContentEncryptorBuilder.build());
    }

    private RecipientInfoGenerator buildRecipientInfoGenerator(X509Certificate recipient)
            throws CMSException, CertificateEncodingException {
        // RSA keys can receive an RSA-key-transport envelope; other key types (e.g. EC) cannot,
        // so fall back to the RFC 8894 §3.2.2 password recipient keyed with the shared challenge
        // password — the response-direction mirror of ScepRequest.decryptData.
        if ("RSA".equalsIgnoreCase(recipient.getPublicKey().getAlgorithm())) {
            logger.debug("Enveloping SCEP response to an RSA recipient via key transport");
            return new JceKeyTransRecipientInfoGenerator(recipient).setProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
        if (challengePassword == null || challengePassword.length == 0) {
            throw new CMSException("Recipient key algorithm " + recipient.getPublicKey().getAlgorithm()
                    + " cannot receive a key-transport envelope and no challenge password is available for password-based enveloping");
        }
        logger
                .debug("Enveloping SCEP response via password recipient (recipient key algorithm {})",
                        recipient.getPublicKey().getAlgorithm());
        return new JcePasswordRecipientInfoGenerator(CMSAlgorithm.AES128_CBC, challengePassword)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    private void createSignedData()
            throws NoSuchAlgorithmException, CertificateEncodingException, OperatorCreationException, CMSException {
        CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
        // Create attributes that will be signed
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = createAttributes();
        String signatureAlgorithmName = AlgorithmUtil
                .getSignatureAlgorithmName(digestAlgorithmOid, signerPrivateKey.getAlgorithm())
                .replace("SHA-", "SHA")
                .replace("WITH", "with");

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName)
                .setProvider(signerProvider)
                .build(signerPrivateKey);
        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME);
        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
        builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)));
        cmsSignedDataGenerator.addSignerInfoGenerator(builder.build(contentSigner, signerCertificate));

        signedResponseData = cmsSignedDataGenerator.generate(responseData, true);
    }

    private Hashtable<ASN1ObjectIdentifier, Attribute> createAttributes() {
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<>();
        ASN1ObjectIdentifier oid;
        Attribute attribute;
        DERSet value;

        // MessageType.CERT_REP
        oid = new ASN1ObjectIdentifier(ScepConstants.id_messageType);
        value = new DERSet(new DERPrintableString(Integer.toString(MessageType.CERT_REP.getValue())));
        attribute = new Attribute(oid, value);
        attributes.put(attribute.getAttrType(), attribute);

        // id_transactionId
        if (transactionId != null) {
            oid = new ASN1ObjectIdentifier(ScepConstants.id_transactionId);
            value = new DERSet(new DERPrintableString(transactionId));
            attribute = new Attribute(oid, value);
            attributes.put(attribute.getAttrType(), attribute);
        }

        // id_pkiStatus
        oid = new ASN1ObjectIdentifier(ScepConstants.id_pkiStatus);
        value = new DERSet(new DERPrintableString(Integer.toString(pkiStatus.getValue())));
        attribute = new Attribute(oid, value);
        attributes.put(attribute.getAttrType(), attribute);

        // id_failInfo
        if (pkiStatus.equals(PkiStatus.FAILURE)) {
            oid = new ASN1ObjectIdentifier(ScepConstants.id_failInfo);
            value = new DERSet(new DERPrintableString(Integer.toString(failInfo.getValue())));
            attribute = new Attribute(oid, value);
            attributes.put(attribute.getAttrType(), attribute);
            // id_scep_failInfoText
            if (failInfoText != null) {
                oid = new ASN1ObjectIdentifier(ScepConstants.id_scep_failInfoText);
                value = new DERSet(new DERPrintableString(failInfoText));
                attribute = new Attribute(oid, value);
                attributes.put(attribute.getAttrType(), attribute);
            }
        }

        // id_senderNonce
        if (senderNonce != null) {
            oid = new ASN1ObjectIdentifier(ScepConstants.id_senderNonce);
            value = new DERSet(new DEROctetString(Base64.getDecoder().decode(senderNonce.getBytes())));
            attribute = new Attribute(oid, value);
            attributes.put(attribute.getAttrType(), attribute);
        }

        // id_recipientNonce
        if (recipientNonce != null) {
            oid = new ASN1ObjectIdentifier(ScepConstants.id_recipientNonce);
            value = new DERSet(new DEROctetString(Base64.getDecoder().decode(recipientNonce.getBytes())));
            attribute = new Attribute(oid, value);
            attributes.put(attribute.getAttrType(), attribute);
        }

        return attributes;
    }
}
