package com.czertainly.core.util;

import com.otilm.api.model.connector.secrets.content.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Component
public class SecretsUtil {

    private static final Logger logger = LoggerFactory.getLogger(SecretsUtil.class);

    private static String encryptionKey;

    private static final SecureRandom random = new SecureRandom();

    @Value("${secrets.encryption.key}")
    public void setEncryptionKeyStatic(String key){
        SecretsUtil.encryptionKey = key;
    }

    private static final String algorithm = "PBEWithSHA256And256BitAES-CBC-BC";
    private static final int iterations = 1000;

    private static final ObjectMapper objectMapper = JsonMapper.builder()
            .findAndAddModules()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .build();

    /**
     * Encrypts and encodes the given secret using the PBEWithSHA256And256BitAES-CBC-BC algorithm.
     * @param secret the secret to encrypt and encode
     * @param secretVersion the version of the encoding
     * @return the encrypted and encoded secret
     */
    public static String encryptAndEncodeSecretString(String secret, SecretEncodingVersion secretVersion) {
        if (secret == null) {
            return null;
        }

        byte[] salt = generateRandomSalt();

        PBEKeySpec keySpec = new PBEKeySpec(encryptionKey.toCharArray(), salt, iterations);
        byte[] encryptedSecret;

        try {
            Cipher c = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            SecretKeyFactory fact = SecretKeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, fact.generateSecret(keySpec));
            encryptedSecret = c.doFinal(secret.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("Padding for " + algorithm + " not found.", e);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException("Illegal block size for " + algorithm, e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + algorithm + " not found", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid specification for " + algorithm, e);
        } catch (BadPaddingException e) {
            throw new IllegalStateException("Bad padding for " + algorithm, e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider not found", e);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Invalid key provided for " + algorithm, e);
        }

        if (secretVersion == SecretEncodingVersion.V1) {
            return encodeSecretStringV1(encryptedSecret, salt, iterations);
        } else {
            throw new IllegalArgumentException("Secret version not supported");
        }

    }

    public static String decodeAndDecryptSecretString(String secret, SecretEncodingVersion secretVersion) {
        byte[] salt;
        int iterations;
        byte[] encryptedSecret;
        if (secretVersion == SecretEncodingVersion.V1) {
            salt = decodeSaltFromSecretStringV1(secret);
            iterations = getIterationsFromSecretStringV1(secret);
            encryptedSecret = decodeEncryptedSecretFromSecretStringV1(secret);
        } else {
            throw new IllegalArgumentException("Secret version not supported");
        }

        PBEKeySpec keySpec = new PBEKeySpec(encryptionKey.toCharArray(), salt, iterations);

        try {
            Cipher c = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            SecretKeyFactory fact = SecretKeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec));
            byte[] decryptedSecret = c.doFinal(encryptedSecret);
            return new String(decryptedSecret);
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("Padding for " + algorithm + " not found.", e);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException("Illegal block size for " + algorithm, e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + algorithm + " not found", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid specification for " + algorithm, e);
        } catch (BadPaddingException e) {
            throw new IllegalStateException("Bad padding for " + algorithm, e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider not found", e);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Invalid key provided for " + algorithm, e);
        }
    }

    public static String calculateSecretContentFingerprint(SecretContent secretContent) throws JsonProcessingException, NoSuchAlgorithmException {
        switch (secretContent.getType()) {
            case BASIC_AUTH -> {
                BasicAuthSecretContent basicAuthSecretContent = (BasicAuthSecretContent) secretContent;
                return CertificateUtil.getThumbprint((basicAuthSecretContent.getUsername() + "|" + basicAuthSecretContent.getPassword()).getBytes(StandardCharsets.UTF_8));
            }
            case API_KEY -> {
                ApiKeySecretContent apiKeySecretContent = (ApiKeySecretContent) secretContent;
                return CertificateUtil.getThumbprint(apiKeySecretContent.getContent().getBytes(StandardCharsets.UTF_8));
            }
            case JWT_TOKEN -> {
                JwtTokenSecretContent jwtTokenSecretContent = (JwtTokenSecretContent) secretContent;
                return CertificateUtil.getThumbprint(jwtTokenSecretContent.getContent().getBytes(StandardCharsets.UTF_8));
            }
            case PRIVATE_KEY -> {
                PrivateKeySecretContent privateKeySecretContent = (PrivateKeySecretContent) secretContent;
                return CertificateUtil.getThumbprint(privateKeySecretContent.getContent().getBytes(StandardCharsets.UTF_8));
            }
            case SECRET_KEY -> {
                SecretKeySecretContent secretKeySecretContent = (SecretKeySecretContent) secretContent;
                return CertificateUtil.getThumbprint(secretKeySecretContent.getContent().getBytes(StandardCharsets.UTF_8));
            }
            case GENERIC -> {
                GenericSecretContent genericSecretContent = (GenericSecretContent) secretContent;
                return CertificateUtil.getThumbprint(genericSecretContent.getContent().getBytes(StandardCharsets.UTF_8));
            }
            case KEY_STORE -> {
                KeyStoreSecretContent keyStoreSecretContent = (KeyStoreSecretContent) secretContent;
                return CertificateUtil.getThumbprint(keyStoreSecretContent.getContent().getBytes(StandardCharsets.UTF_8));
            }
            case KEY_VALUE -> {
                KeyValueSecretContent keyValueSecretContent = (KeyValueSecretContent) secretContent;
                return CertificateUtil.getThumbprint(objectMapper.writeValueAsBytes(keyValueSecretContent.getContent()));
            }
            default ->
                    throw new IllegalArgumentException("Unsupported secret content type: " + secretContent.getType());
        }
    }

    /**
     * Encoded the secret value into string
     * V1|secret|salt|count
     * @param secret value to be encoded
     * @param salt used salt
     * @param count number of iterations
     * @return encoded string
     */
    private static String encodeSecretStringV1(byte[] secret, byte[] salt, int count) {
        StringBuilder encoded = new StringBuilder();
        encoded.append(SecretEncodingVersion.V1.getVersion());
        encoded.append("|");
        encoded.append(Base64.getEncoder().encodeToString(secret));
        encoded.append("|");
        encoded.append(Base64.getEncoder().encodeToString(salt));
        encoded.append("|");
        encoded.append(count);

        if (logger.isTraceEnabled()) {
            logger.trace("Encoded data: " + encoded);
        }

        return encoded.toString();
    }

    private static byte[] decodeSaltFromSecretStringV1(String secret) {
        if (isSecretStringV1(secret)) {
            String[] parts = secret.split("\\|");
            return Base64.getDecoder().decode(parts[2]);
        } else {
            throw new IllegalArgumentException("Secret string is not in the correct format");
        }
    }

    private static int getIterationsFromSecretStringV1(String secret) {
        if (isSecretStringV1(secret)) {
            String[] parts = secret.split("\\|");
            return Integer.parseInt(parts[3]);
        } else {
            throw new IllegalArgumentException("Secret string is not in the correct format");
        }
    }

    private static byte[] decodeEncryptedSecretFromSecretStringV1(String secret) {
        if (isSecretStringV1(secret)) {
            String[] parts = secret.split("\\|");
            return Base64.getDecoder().decode(parts[1]);
        } else {
            throw new IllegalArgumentException("Secret string is not in the correct format");
        }
    }

    private static boolean isSecretStringV1(String secret) {
        String[] parts = secret.split("\\|");
        if (parts.length != 4) {
            return false;
        }
        return parts[0].equals("v1");
    }

    /**
     * Generate random salt for encryption
     * @return salt
     */
    private static byte[] generateRandomSalt() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return bytes;
    }

}
