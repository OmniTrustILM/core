package com.otilm.core.service.writer.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.util.CertificateUtil;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes a discovered key into the inventory and stamps the staged row that produced it.
 *
 * <p>
 * {@code REQUIRES_NEW} per item: one key that cannot be written must not take the batch's other keys with it, and the
 * stamp has to survive whatever the caller does next.
 */
@Service
public class DiscoveredKeyWriter {

    private final CryptographicKeyRepository keyRepository;
    private final CryptographicKeyItemRepository keyItemRepository;
    private final DiscoveryItemRepository itemRepository;

    public DiscoveredKeyWriter(CryptographicKeyRepository keyRepository,
            CryptographicKeyItemRepository keyItemRepository, DiscoveryItemRepository itemRepository) {
        this.keyRepository = keyRepository;
        this.keyItemRepository = keyItemRepository;
        this.itemRepository = itemRepository;
    }

    /**
     * Records the key this item reported, or finds the record it already is, and stamps the item with it.
     *
     * @throws UnusableKeyException when the payload cannot identify a key at all
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void importKey(DiscoveryItem item, DiscoveredKeyDto key) {
        String fingerprint = identityOf(key);
        UUID keyUuid = keyItemRepository
                .findByFingerprint(fingerprint)
                .map(CryptographicKeyItem::getKeyUuid)
                .orElseGet(() -> record(item, key, fingerprint));
        itemRepository.markImported(item.getUuid(), keyUuid, OffsetDateTime.now(ZoneOffset.UTC));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markFailed(UUID itemUuid, String reason) {
        itemRepository.markFailed(itemUuid, reason, OffsetDateTime.now(ZoneOffset.UTC));
    }

    /**
     * What identifies a key across everything that reports it.
     *
     * <p>
     * Computed from the material whenever there is material, with the call {@code CertificateHandler} makes for a
     * certificate's public key: the v2 contract asks a connector for an intrinsic fingerprint but does not say how to
     * compute one, so trusting the connector's string would file the same key twice — once as a key, once as the key of
     * a certificate carrying it. A connector's own value identifies only the key types that have no public part, which
     * no certificate can collide with.
     */
    private String identityOf(DiscoveredKeyDto key) {
        String material = key.getPublicKey();
        if (material != null && !material.isBlank()) {
            try {
                byte[] encoded = Base64.getDecoder().decode(material);
                return CertificateUtil
                        .getThumbprint(Base64.getEncoder().encodeToString(encoded).getBytes(StandardCharsets.UTF_8));
            } catch (IllegalArgumentException e) {
                throw new UnusableKeyException("The reported public key was not valid Base64.", e);
            } catch (NoSuchAlgorithmException e) {
                throw new UnusableKeyException("The key's fingerprint could not be computed.", e);
            }
        }
        if (key.getFingerprint() == null || key.getFingerprint().isBlank()) {
            throw new UnusableKeyException(
                    "The key was reported without public key material and without a fingerprint, so it cannot be "
                            + "told apart from any other.");
        }
        return key.getFingerprint();
    }

    /**
     * Writes the key. The insert resolves a fingerprint collision rather than failing on it: another run importing the
     * same key concurrently is the expected case, not an error, and the key it wrote is the one both items point at.
     */
    private UUID record(DiscoveryItem item, DiscoveredKeyDto key, String fingerprint) {
        CryptographicKey parent = new CryptographicKey();
        parent.setName(nameFor(item, fingerprint));
        parent.setDescription("Discovered as " + item.getUniqueRef());
        keyRepository.save(parent);

        CryptographicKeyItem keyItem = keyItem(parent, item, key, fingerprint);
        if (keyItemRepository.insertWithFingerprintConflictResolve(keyItem) == 1) {
            return parent.getUuid();
        }
        UUID surviving = keyItemRepository
                .findByFingerprint(fingerprint)
                .map(CryptographicKeyItem::getKeyUuid)
                .orElseThrow(() -> new IllegalStateException(
                        "A key with the same fingerprint was committed concurrently but could no longer be read"));
        keyRepository.delete(parent);
        return surviving;
    }

    private CryptographicKeyItem keyItem(CryptographicKey parent, DiscoveryItem item, DiscoveredKeyDto key,
            String fingerprint) {
        LocalDateTime now = LocalDateTime.now(ZoneId.systemDefault());
        CryptographicKeyItem keyItem = new CryptographicKeyItem();
        keyItem.setUuid(UUID.randomUUID());
        keyItem.setName(parent.getName());
        keyItem.setKey(parent);
        keyItem.setKeyUuid(parent.getUuid());
        keyItem.setType(key.getType());
        keyItem.setKeyAlgorithm(key.getAlgorithm());
        keyItem.setFormat(key.getPublicKeyFormat());
        keyItem.setKeyData(key.getPublicKey());
        keyItem.setLength(key.getLength() == null ? 0 : key.getLength());
        keyItem.setFingerprint(fingerprint);
        // Discovered, not managed: the platform holds no private part and runs no lifecycle on it, so the state says
        // what is true of the key itself rather than of anything this platform does with it.
        keyItem.setState(KeyState.ACTIVE);
        keyItem.setEnabled(true);
        // Where the provider found it. Dropped here it is unrecoverable: the staged row is the only place it exists.
        keyItem.setKeyMeta(item.getMeta());
        keyItem.setCreatedAt(now);
        keyItem.setUpdatedAt(now);
        return keyItem;
    }

    /**
     * A name an operator can find the key by. The reference is what the provider calls the place it found it, which is
     * more use than a digest; the fingerprint's head disambiguates two keys at one location.
     */
    private String nameFor(DiscoveryItem item, String fingerprint) {
        String head = fingerprint.length() > 8 ? fingerprint.substring(0, 8) : fingerprint;
        return "discovered_%s_%s".formatted(item.getUniqueRef(), head);
    }

    /** A payload that cannot identify a key. Its message is written for the operator who reads the item. */
    public static class UnusableKeyException extends IllegalArgumentException {

        public UnusableKeyException(String message) {
            super(message);
        }

        public UnusableKeyException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
