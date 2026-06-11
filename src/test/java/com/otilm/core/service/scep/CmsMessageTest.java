package com.otilm.core.service.scep;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.core.scep.MessageType;
import com.otilm.core.service.scep.message.ScepConstants;
import com.otilm.core.service.scep.message.ScepRequest;
import com.otilm.core.util.CertificateUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Hashtable;

public class CmsMessageTest {

    private final String SENDER_NONCE = "cVpmdzRXdDBPV25JNVA0Y1pMcHZvSzJuUG9fUlR2cXhZT0RBOUdGdlE2cw==";
    private final String TRANSACTION_ID = "361ba25258bfc72fe6cf8aa70f75e21facd8fc3d";

    @Test
    public void testScepRequestParsing() throws CertificateException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, OperatorCreationException, CMSException, ScepException {
        CMSProcessableByteArray cmsProcessableByteArray = generateEnvelopedData();
        CMSSignedData signedData = createSignedData(cmsProcessableByteArray);
        ScepRequest scepRequest = new ScepRequest(signedData.getEncoded());
        Assertions.assertEquals(scepRequest.getMessageType(), MessageType.PKCS_REQ);
        Assertions.assertEquals(scepRequest.getSenderNonce(), SENDER_NONCE);
        Assertions.assertEquals(scepRequest.getTransactionId(), TRANSACTION_ID);
    }

    private static CMSProcessableByteArray generateEnvelopedData() throws IOException, CMSException {

        Security.addProvider(new BouncyCastleProvider());

        String password = "mysecretpassword";
        byte[] csrBytes = Base64.getDecoder().decode("MIICUzCCATsCAQAwDjEMMAoGA1UEAwwDeDExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx3yEn1ivUp4etk3kdNrRXNP5PeIpTYobGj4lQrW57rsj9hhOhY/SwaeCu6sYPVvYIXPWnlc4tTafjcen/8Ikc7pY2NuzD0HaIAOujblcMKT2KAKA/OU+RrI2o/swU9UmEQ2wYveNYCGobimt/foURrB9opeDCx3pFXkddYsXAziaWu3AQIF5gIf/b+r7hYRIXh8V/u01t6FCnpBWCtdmYVrJ5e8KZw0yqptNpgDK1plu+8AR5tviP/vgrpBquwzNsVREsnRZJxOM6rXq9rG5scoqO+gxdsm6+EqfRiGiBvcaIr+Zpv81ryfiABLdixvyhoZ//3o8rAU0O7Pjm7HTxwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAKM6lsrzME64G90fm98Zdgxe6IMBmIWTzA03V0OWGTYjYjYZbfsddAQAO1h3EMKjPl5nFaXkTVGoq8G4ZHvdu2fX72dyNJaGG+mG89uoW9iFd2US+nU5aN8xSpPx1k89DhPat/q5kdOwIIGAXvIbLWSXGx9A25DxdqvouuhDT7NJZqGTsPivHuFXgP3Mb1HTr/qnshx+shTnJ+FnYncARl3KmflCyCPC4NBKcorWl8kVFRDw2Y7aeg3a1hV3EJJfElFSwlmmT2Y/VDuZcMalFnnAKq2NqXByBlK9s7s67sMKzsqaAGwlg3TT37v6QN6L2q0zUU6egAuA4Av2LR6nJkw=".getBytes());
        PasswordRecipientInfoGenerator priGen = new JcePasswordRecipientInfoGenerator(
                CMSAlgorithm.AES128_CBC, password.toCharArray());

        CMSProcessableByteArray cmsData = new CMSProcessableByteArray(csrBytes);
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        edGen.addRecipientInfoGenerator(priGen);

        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BC").build();
        CMSEnvelopedData cmsEnvelope = edGen.generate(cmsData, encryptor);
        return new CMSProcessableByteArray(cmsEnvelope.getEncoded());
    }

    private CMSSignedData createSignedData(CMSProcessableByteArray responseData) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CMSException, InvalidKeySpecException {
        CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
        // Create attributes that will be signed
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = createAttributes();

        X509Certificate signerCertificate = CertificateUtil.parseCertificate("MIIB5TCCAYqgAwIBAgIUQWJcNhcZ8rdJ8d+Y0/zjDauIDvAwCgYIKoZIzj0EAwIwNzELMAkGA1UEBhMCSU4xEzARBgNVBAgMClRhbWlsIE5hZHUxEzARBgNVBAcMCkNvaW1iYXRvcmUwHhcNMjMwNDE5MTAxNjI0WhcNMjQwNDE4MTAxNjI0WjA3MQswCQYDVQQGEwJJTjETMBEGA1UECAwKVGFtaWwgTmFkdTETMBEGA1UEBwwKQ29pbWJhdG9yZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1ILz/GLiGtx9JIoFesLv6ssTrBr5W1c+FUuCKUGjvZpM8l5wAbC9TJaYwcA3B45iuTAzmTTOoPCwrr/ALGhoyjdDByMB0GA1UdDgQWBBT4VuTPGMKzKGqAYgAtq7eFR+nPpzAfBgNVHSMEGDAWgBT4VuTPGMKzKGqAYgAtq7eFR+nPpzAOBgNVHQ8BAf8EBAMCBaAwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAoGCCqGSM49BAMCA0kAMEYCIQCUxvkZzxraytwbhhoCafIzHaj62EGVbxW5bUlvLTZPIwIhAJ6eFFyO8f9udwCHUt+4aMQGyBHCISbgvgvejMU6NSZU");
        String signatureAlgorithmName = "SHA256WithECDSA";

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgR7jrC6SUkUlWEouD/5yVwazngKD0mHjA4YsOhesg+fShRANCAASNSC8/xi4hrcfSSKBXrC7+rLE6wa+VtXPhVLgilBo72aTPJecAGwvUyWmMHANweOYrkwM5k0zqDwsK6/wCxoaM"));
        KeyFactory kf = KeyFactory.getInstance("EC");
        PrivateKey signerPrivateKey = kf.generatePrivate(keySpec);

        Security.addProvider(new BouncyCastleProvider());


        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signerPrivateKey);
        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
        builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)));
        cmsSignedDataGenerator.addSignerInfoGenerator(builder.build(contentSigner, signerCertificate));

        JcaCertStore certStore = new JcaCertStore(Collections.singletonList(signerCertificate));
        cmsSignedDataGenerator.addCertificates(certStore);

        return cmsSignedDataGenerator.generate(responseData, true);
    }

    private Hashtable<ASN1ObjectIdentifier, Attribute> createAttributes() {
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<>();
        ASN1ObjectIdentifier oid;
        Attribute attribute;
        DERSet value;

        oid = new ASN1ObjectIdentifier(ScepConstants.id_messageType);
        value = new DERSet(new DERPrintableString(Integer.toString(MessageType.PKCS_REQ.getValue())));
        attribute = new Attribute(oid, value);
        attributes.put(attribute.getAttrType(), attribute);

        oid = new ASN1ObjectIdentifier(ScepConstants.id_transactionId);
        value = new DERSet(new DERPrintableString(TRANSACTION_ID));
        attribute = new Attribute(oid, value);
        attributes.put(attribute.getAttrType(), attribute);

        oid = new ASN1ObjectIdentifier(ScepConstants.id_senderNonce);
        value = new DERSet(new DEROctetString(Base64.getDecoder().decode(SENDER_NONCE)));
        attribute = new Attribute(oid, value);
        attributes.put(attribute.getAttrType(), attribute);

        return attributes;
    }


}
