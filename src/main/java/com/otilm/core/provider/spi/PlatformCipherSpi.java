package com.otilm.core.provider.spi;

import com.otilm.core.provider.PlatformCipherService;
import com.otilm.core.provider.key.PlatformPrivateKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class PlatformCipherSpi extends CipherSpi {

    private static final Logger log = LoggerFactory.getLogger(PlatformCipherSpi.class);

    private final PlatformCipherService cipherService;
    private PlatformPrivateKey privateKey;

    private int operationMode;

    public PlatformCipherSpi(PlatformCipherService cipherService) {
        this.cipherService = cipherService;
    }

    @Override
    protected byte[] engineUpdate(byte[] b, int off, int len) {
        return null;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] encryptedData, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if (operationMode == Cipher.DECRYPT_MODE) {;
            return cipherService.decrypt(
                    encryptedData,
                    privateKey
            );
        } else {
            throw new IllegalStateException("Encryption is not supported by this provider (yet)");
        }

    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        // Method is not implemented. The current implementation involves only for SCEP related items
        // And this method is not used.
        // This method should be implemented when the complete encryption and decryption is processed through the CZERTAINLY Provider
        return 0;
    }

    @Override
    protected int engineGetBlockSize() {
        //Method is not implemented. The current implementation involves only for SCEP related items
        // And this method is not used.
        // This method should be implemented when the complete encryption and decryption is processed through the Platform Provider
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        //Method is not implemented. The current implementation involves only for SCEP related items
        // And this method is not used.
        // This method should be implemented when the complete encryption and decryption is processed through the Platform Provider
        return null;
    }

    @Override
    protected int engineGetOutputSize(int value) {
        // Method is not implemented. The current implementation involves only for SCEP related items
        // And this method is not used.
        // This method should be implemented when the complete encryption and decryption is processed through the Platform Provider
        return 0;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        // Method is not implemented. The current implementation involves only for SCEP related items
        // And this method is not used.
        // This method should be implemented when the complete encryption and decryption is processed through the Platform Provider
        return null;
    }

    @Override
    protected void engineInit(int operationMode, Key key, SecureRandom random) throws InvalidKeyException {
        if (operationMode != Cipher.DECRYPT_MODE && operationMode != Cipher.UNWRAP_MODE) {
            throw new IllegalArgumentException("Unsupported Operation Mode: " + operationMode);
        }
        if (key == null) {
            throw new InvalidKeyException("Invalid null private key");
        }
        this.operationMode = operationMode;
        this.privateKey = (PlatformPrivateKey) key;
        log.debug("Initializing cipher with operation mode: {} and key: {}", operationMode, privateKey.getKeyUuid());
    }

    @Override
    protected void engineInit(int operationMode, Key key, AlgorithmParameterSpec arg2, SecureRandom arg3)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        // Method is not implemented. The current implementation involves only for SCEP related items
        // And this method is not used.
        // This method should be implemented when the complete encryption and decryption is processed through the Platform Provider
    }

    @Override
    protected void engineInit(int operationMode, Key key, AlgorithmParameters arg2, SecureRandom arg3)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        // Method is not implemented. The current implementation involves only for SCEP related items
        // And this method is not used.
        // This method should be implemented when the complete encryption and decryption is processed through the Platform Provider
    }

    @Override
    protected void engineSetMode(String operationMode) throws NoSuchAlgorithmException {
        // Method is not implemented. The current implementation involves only for SCEP related items
        // And this method is not used.
        // This method should be implemented when the complete encryption and decryption is processed through the Platform Provider
    }

    @Override
    protected void engineSetPadding(String operationMode) throws NoSuchPaddingException {
        // Method is not implemented. The current implementation involves only for SCEP related items
        // And this method is not used.
        // This method should be implemented when the complete encryption and decryption is processed through the Platform Provider
    }

}
