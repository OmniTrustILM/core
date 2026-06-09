package com.otilm.core.service.cmp;

import com.otilm.api.model.common.attribute.v2.BaseAttributeV2;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureResponseData;
import com.otilm.core.service.cmp.mock.CertTestUtil;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.common.Json;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.cmp.*;
import org.bouncycastle.cert.crmf.*;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class CmpTestUtil {

    public static WireMockServer createSigningPlatform() {
        // prepare mock server - for cryptographic provider
        WireMockServer mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        // -- if there is a need something to sign (mock server is called)
        // see https://docs.czertainly.com/api/core-cryptographic-operations/#tag/Cryptographic-Operations-Controller/operation/signData
        // see https://docs.czertainly.com/api/connector-cryptography-provider/#tag/Cryptographic-Operations/operation/signData
        SignDataResponseDto singDataRsp = new SignDataResponseDto();
        SignatureResponseData singedDataAsBytes = new SignatureResponseData();
        singedDataAsBytes.setData("test".getBytes());
        singDataRsp.setSignatures(List.of(singedDataAsBytes));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/sign"))
                .willReturn(WireMock.okJson(Json.write(singDataRsp))));
        return mockServer;
    }

    public static WireMockServer createIssuingPlatform() {
        // prepare mock server - for cryptographic provider
        WireMockServer mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        // -- if there is a need something to sign (mock server is called)
        // see https://docs.czertainly.com/api/core-cryptographic-operations/#tag/Cryptographic-Operations-Controller/operation/signData
        // see https://docs.czertainly.com/api/connector-cryptography-provider/#tag/Cryptographic-Operations/operation/signData
        SignDataResponseDto singDataRsp = new SignDataResponseDto();
        SignatureResponseData singedDataAsBytes = new SignatureResponseData();
        singedDataAsBytes.setData("test".getBytes());
        singDataRsp.setSignatures(List.of(singedDataAsBytes));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/sign"))
                .willReturn(WireMock.okJson(Json.write(singDataRsp))));


        mockServer.stubFor(WireMock
                //v2/authorityProvider/authorities/{uuid}/certificates/issue/attributes/validate
                //v2/authorityProvider/authorities/{uuid}/certificates/issue/attributes
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
                .willReturn(WireMock.okJson(Json.write(Boolean.TRUE))));
        List<BaseAttributeV2> listOfAttributes = new ArrayList<>();
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.okJson(Json.write(listOfAttributes))));

//        mockServer.stubFor(WireMock
//                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
//                .willReturn(WireMock.okJson("{}")));
        return mockServer;
    }

    // -- pki message api
    public static ProtectedPKIMessage createSignatureBasedMessage(String transactionId,
                                                                  PrivateKey privateKey,
                                                                  PKIBody body)
            throws Exception {
        String signAlgorithmName = CertTestUtil.getSigningAlgNameFromKeyAlg(privateKey.getAlgorithm());
        ContentSigner msgSigner = new JcaContentSignerBuilder(signAlgorithmName)//
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(privateKey);
        return createPkiMessageBuilder(transactionId, body)
                .build(msgSigner);
    }

    public static ProtectedPKIMessage createMacBasedMessage(String transactionId,
                                                      String sharedSecret, PKIBody body)
            throws CRMFException, CMPException {
        JcePKMACValuesCalculator jcePkmacCalc = new JcePKMACValuesCalculator();
        jcePkmacCalc.setup(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26")), // SHA1
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7"))); // HMAC/SHA1
        MacCalculator macCalculator = new PKMACBuilder(jcePkmacCalc)
                .setIterationCount(1000)
                .setSaltLength(25)
                //.setParameters(new PBMParameter(salt, owf, iterCount, macAlg))
                .build(sharedSecret.toCharArray());
        return createPkiMessageBuilder(transactionId, body)
                .build(macCalculator);
    }

    public static ProtectedPKIMessageBuilder createPkiMessageBuilder(
            String transactionId, PKIBody body) {
        X500Name issuerDN = new X500Name("CN=ManagementCA");
        X500Name userDN = new X500Name("CN=user");
        byte[] senderNonce = "12345".getBytes();
        GeneralName sender = new GeneralName(userDN);
        GeneralName recipient = new GeneralName(issuerDN);

        return new ProtectedPKIMessageBuilder(sender, recipient)
                .setMessageTime(new Date())
                .setSenderNonce(senderNonce)
                .setTransactionID(transactionId.getBytes())
                .setBody(body);
    }

    public static PKIBody createRevocationBody(BigInteger serialNumber) throws IOException {
        // Just preparations
        X500Name issuerDN = new X500Name("CN=ManagementCA");
        X500Name userDN = new X500Name("CN=user");

        // Cert template
        CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
        myCertTemplate.setIssuer(issuerDN);
        myCertTemplate.setSubject(userDN);
        myCertTemplate.setSerialNumber(new ASN1Integer(serialNumber));

        // Extension with revocation reason
        ExtensionsGenerator extGenerator = new ExtensionsGenerator();
        extGenerator.addExtension(Extension.reasonCode,
                false, CRLReason.lookup(CRLReason.cessationOfOperation));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(myCertTemplate.build());
        v.add(extGenerator.generate());
        RevReqContent myRevReqContent = new RevReqContent(
                RevDetails.getInstance(new DERSequence(v)));
        return new PKIBody(PKIBody.TYPE_REVOCATION_REQ, myRevReqContent);
    }

    public static PKIBody createCertConfBody(X509CertificateHolder cert, BigInteger certReqId) throws
            OperatorCreationException, CMPException {
        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
                .addAcceptedCertificate(cert, certReqId)
                .build(new JcaDigestCalculatorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build());
        return new PKIBody(PKIBody.TYPE_CERT_CONFIRM, content.toASN1Structure());
    }

    // -- crypto objects
    public static KeyPair generateKeyPairEC() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME); // Initialize to generate asymmetric keys to be used with one of the Elliptic Curve algorithms
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1"); // using domain parameters specified by safe curve spec of secp384r1
        keyPairGenerator.initialize(ecSpec, new SecureRandom("_n3coHodn@Kryptickeho!".getBytes()));
        return keyPairGenerator.generateKeyPair(); // Generate asymmetric keys.
    }

    public static X509CertificateHolder makeV3Certificate(BigInteger serialNumber, KeyPair subKP,
                                                           String _subDN, KeyPair issKP,
                                                           String _issDN) throws OperatorCreationException, CertException {
//58e62ee31e12477faea056d05c3805938b489bb3
        PublicKey subPub = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey issPub = issKP.getPublic();

        X509v3CertificateBuilder v1CertGen = new JcaX509v3CertificateBuilder(
                new X500Name(_issDN),
                serialNumber,
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
                new X500Name(_subDN),
                subPub);

        ContentSigner signer = new JcaContentSignerBuilder("SHA384withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issPriv);

        X509CertificateHolder certHolder = v1CertGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issPub);

        assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
    }

    public static void derEncodeToStream(ASN1Object obj, OutputStream stream) {
        try {
            obj.encodeTo(stream, ASN1Encoding.DER);
            stream.close();
        } catch (IOException e) {
            throw new CMPRuntimeException("unable to DER encode object: " + e.getMessage(), e);
        }
    }

    public static DigestCalculator createMessageDigest(X509CertificateHolder x509certificate)
            throws CMPException, OperatorCreationException {
        CMPCertificate cmpCert = new CMPCertificate(x509certificate.toASN1Structure());
        AlgorithmIdentifier digAlg = new DefaultDigestAlgorithmIdentifierFinder().find(x509certificate.getSignatureAlgorithm());
        if (digAlg == null) {
            throw new CMPException("cannot find algorithm for digest from signature");
        }

        DigestCalculator digester;
        DigestCalculatorProvider digesterProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        try { digester = digesterProvider.get(digAlg); }
        catch (OperatorCreationException e) {
            throw new CMPException("unable to create digest: " + e.getMessage(), e);
        }
        derEncodeToStream(cmpCert, digester.getOutputStream());
        return digester;
    }

    public static PKIBody createCrmfBody(
            KeyPair keyPair, long certReqId)
            throws IOException, CRMFException, OperatorCreationException {
        return createCrmfBody(keyPair, certReqId, PKIBody.TYPE_INIT_REQ);
    }

    public static PKIBody createCrmfBody(
            KeyPair keyPair, long certReqId, int pkiBodyType)
            throws IOException, CRMFException, OperatorCreationException {
        CertificateRequestMessageBuilder msgbuilder = new CertificateRequestMessageBuilder(BigInteger.valueOf(certReqId));
        X509NameEntryConverter dnconverter = new X509DefaultEntryConverter();
        X500Name issuerDN = X500Name.getInstance(new org.bouncycastle.asn1.x509.X509Name("CN=ManagementCA").toASN1Primitive());
        X500Name subjectDN = X500Name.getInstance(new X509Name("CN=user", dnconverter).toASN1Primitive());
        msgbuilder.setIssuer(issuerDN);
        msgbuilder.setSubject(subjectDN);
        final byte[]                  bytes = keyPair.getPublic().getEncoded();
        final ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        final ASN1InputStream dIn = new ASN1InputStream(bIn);
        final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((org.bouncycastle.asn1.ASN1Sequence)dIn.readObject());
        msgbuilder.setPublicKey(keyInfo);
        GeneralName sender = new GeneralName(subjectDN);
        msgbuilder.setAuthInfoSender(sender);
        Control control = new RegTokenControl("foo123");
        msgbuilder.addControl(control);
        Provider prov = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner popsigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider(prov).build(keyPair.getPrivate());
        msgbuilder.setProofOfPossessionSigningKeySigner(popsigner);
        CertificateRequestMessage msg = msgbuilder.build();
        org.bouncycastle.asn1.crmf.CertReqMessages msgs = new org.bouncycastle.asn1.crmf.CertReqMessages(msg.toASN1Structure());
        org.bouncycastle.asn1.cmp.PKIBody pkibody = new org.bouncycastle.asn1.cmp.PKIBody(pkiBodyType, msgs);
        return pkibody;
    }

    public static ProtectedPKIMessage createKur(
            String transactionId, BigInteger certReqId, KeyPair keyPair) throws Exception {
        X500Name issuerDN = new X500Name("CN=ManagementCA");
        X500Name userDN = new X500Name("CN=cmp-test-dev.ir.cz");

        final byte[]                  bytes = keyPair.getPublic().getEncoded();
        final ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        final ASN1InputStream dIn = new ASN1InputStream(bIn);
        final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((org.bouncycastle.asn1.ASN1Sequence)dIn.readObject());

        final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

        AttributeTypeAndValue atv = new AttributeTypeAndValue(CMPObjectIdentifiers.regCtrl_oldCertID,
                new CertId(new GeneralName(issuerDN), new ASN1Integer(certReqId)));

        CertificateRequestMessageBuilder builder = new JcaCertificateRequestMessageBuilder(certReqId)
                .setIssuer(issuerDN)
                .setSubject(userDN)
                .setPublicKey(keyInfo)
                .setAuthInfoSender(new GeneralName(userDN))
                .addControl(new RegTokenControl("foo123"))
                .addControl(new Control(){
                    @Override public ASN1ObjectIdentifier getType() { return atv.getType(); }
                    @Override public ASN1Encodable getValue() { return atv.getValue(); }
                })
                .setProofOfPossessionSigningKeySigner(contentSigner);

        return new ProtectedPKIMessageBuilder(
                new GeneralName(userDN), new GeneralName(issuerDN))
                .setTransactionID(transactionId.getBytes())
                .setBody(new PKIBody(PKIBody.TYPE_KEY_UPDATE_REQ,
                        new CertReqMessages(builder.build().toASN1Structure())))
                //.addCMPCertificate(singerCert)
                .build(contentSigner);
    }

    public static ProtectedPKIMessage createKur(String sharedSecret,
            String transactionId, BigInteger certReqId, KeyPair keyPair) throws Exception {
        X500Name issuerDN = new X500Name("CN=ManagementCA");
        X500Name userDN = new X500Name("CN=cmp-test-dev.ir.cz");

        final byte[]                  bytes = keyPair.getPublic().getEncoded();
        final ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        final ASN1InputStream dIn = new ASN1InputStream(bIn);
        final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((org.bouncycastle.asn1.ASN1Sequence)dIn.readObject());

        JcePKMACValuesCalculator jcePkmacCalc = new JcePKMACValuesCalculator();
        jcePkmacCalc.setup(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26")), // SHA1
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7"))); // HMAC/SHA1
        MacCalculator macCalculator = new PKMACBuilder(jcePkmacCalc)
                .setIterationCount(1000)
                .setSaltLength(25)
                //.setParameters(new PBMParameter(salt, owf, iterCount, macAlg))
                .build(sharedSecret.toCharArray());

        AttributeTypeAndValue atv = new AttributeTypeAndValue(CMPObjectIdentifiers.regCtrl_oldCertID,
                new CertId(new GeneralName(issuerDN), new ASN1Integer(certReqId)));

        CertificateRequestMessageBuilder builder = new JcaCertificateRequestMessageBuilder(certReqId)
                .setIssuer(issuerDN)
                .setSubject(userDN)
                .setPublicKey(keyInfo)
                .setAuthInfoSender(new GeneralName(userDN))
                .addControl(new RegTokenControl("foo123"))
                .addControl(new Control(){
                    @Override public ASN1ObjectIdentifier getType() { return atv.getType(); }
                    @Override public ASN1Encodable getValue() { return atv.getValue(); }
                })
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(keyPair.getPrivate()));

        return new ProtectedPKIMessageBuilder(
                new GeneralName(userDN), new GeneralName(issuerDN))
                .setTransactionID(transactionId.getBytes())
                .setBody(new PKIBody(PKIBody.TYPE_KEY_UPDATE_REQ,
                        new CertReqMessages(builder.build().toASN1Structure())))
                //.addCMPCertificate(singerCert)
                .build(macCalculator);
    }

    public static CertificateRequestMessageBuilder createCrmf(X500Name issuerDN, X500Name subjectDN)
            throws NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException, NoSuchProviderException {
        CertificateRequestMessageBuilder msgBuilder = new CertificateRequestMessageBuilder(
                BigInteger.valueOf(1L));
        msgBuilder.setIssuer(issuerDN);//"CN=ManagementCA"
        msgBuilder.setSubject(subjectDN);//"CN=user"
        msgBuilder.setAuthInfoSender(new GeneralName(subjectDN));
        msgBuilder.setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);
        KeyPair keyPair = generateKeyPairEC();
        byte[]                  bytes = keyPair.getPublic().getEncoded();
        ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream         dIn = new ASN1InputStream(bIn);
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((org.bouncycastle.asn1.ASN1Sequence)dIn.readObject());
        dIn.close();
        msgBuilder.setPublicKey(keyInfo);
        return msgBuilder;
    }
}
