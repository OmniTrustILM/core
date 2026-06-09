package com.otilm.core.provider.spi;

import com.otilm.core.provider.CzertainlySignatureService;
import com.otilm.core.provider.key.CzertainlyPrivateKey;
import com.otilm.core.provider.key.CzertainlyPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.security.*;

public class CzertainlySignatureSpi extends SignatureSpi {

    private static final Logger log = LoggerFactory.getLogger(CzertainlySignatureSpi.class);
    private final CzertainlySignatureService signatureService;
    private CzertainlyPrivateKey privateKey;

    private CzertainlyPublicKey publicKey;

    private boolean isSign;

    private boolean isVerify;

    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public CzertainlySignatureSpi(CzertainlySignatureService signatureService) {
        this.signatureService = signatureService;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("Invalid null private key");
        }
        if (!(privateKey instanceof CzertainlyPrivateKey)) {
            throw new InvalidKeyException("Private key must be CzertainlyPrivateKey. Cannot be" + privateKey.getClass().getName());
        }
        this.privateKey = (CzertainlyPrivateKey) privateKey;
        this.isSign = true;
        log.debug("Initializing signature with private key: {}", this.privateKey.getKeyUuid());
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] bytes, int offset, int len) throws SignatureException {
        buffer.write(bytes, offset, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!isSign)
            throw new SignatureException("The signature service is not set up for signing");

        byte[] dataToSign;
        dataToSign = buffer.toByteArray();
        buffer = new ByteArrayOutputStream();

        return signatureService.sign(
                privateKey,
                dataToSign
        );
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey == null) {
            throw new InvalidKeyException("Invalid null public key");
        }
        this.publicKey = (CzertainlyPublicKey) publicKey;
        this.isVerify = true;
        log.debug("Initializing signature verification with public key: {}", this.publicKey.getKeyUuid());
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (!isVerify)
            throw new SignatureException("The signature service is not set up for verification");

        byte[] dataToVerify;
        dataToVerify = buffer.toByteArray();

        return signatureService.verify(publicKey, sigBytes, dataToVerify);
    }

    @Override
    protected void engineSetParameter(String s, Object o) throws InvalidParameterException {

    }

    @Override
    protected Object engineGetParameter(String s) throws InvalidParameterException {
        return null;
    }

}
