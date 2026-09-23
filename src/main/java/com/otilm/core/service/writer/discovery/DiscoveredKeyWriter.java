package com.otilm.core.service.writer.discovery;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.service.handler.discovery.DiscoveredKeyIdentity;
import com.otilm.core.service.handler.discovery.UnusableDiscoveredKeyException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes a discovered key into the inventory and stamps the staged row that produced it.
 *
 * <p>
 * Both entry points are one item's unit of work, and the caller runs each in its own transaction: one key that cannot
 * be written must not take the batch's other keys with it, and the stamp has to survive whatever the caller does next.
 * The boundary is the caller's because a writer holds @Modifying calls, which need an ambient transaction rather than
 * one they open themselves.
 */
@Service
public class DiscoveredKeyWriter {

    private final CryptographicKeyRepository keyRepository;
    private final CryptographicKeyItemRepository keyItemRepository;
    private final DiscoveryItemRepository itemRepository;
    private final ObjectMapper objectMapper;

    public DiscoveredKeyWriter(CryptographicKeyRepository keyRepository,
            CryptographicKeyItemRepository keyItemRepository, DiscoveryItemRepository itemRepository,
            ObjectMapper objectMapper) {
        this.keyRepository = keyRepository;
        this.keyItemRepository = keyItemRepository;
        this.itemRepository = itemRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * Records the key this item reported, or finds the record it already is, and stamps the item with it.
     *
     * @throws UnusableDiscoveredKeyException when the payload cannot identify a key at all
     */
    @Transactional
    public void importKey(DiscoveryItem item, DiscoveredKeyDto key) {
        String fingerprint = DiscoveredKeyIdentity.of(key);
        UUID keyUuid = keyItemRepository
                .findByFingerprint(fingerprint)
                .map(CryptographicKeyItem::getKeyUuid)
                .orElseGet(() -> record(item, key, fingerprint));
        itemRepository.markImported(item.getUuid(), keyUuid, OffsetDateTime.now(ZoneOffset.UTC));
    }

    @Transactional
    public void markFailed(UUID itemUuid, String reason) {
        itemRepository.markFailed(itemUuid, reason, OffsetDateTime.now(ZoneOffset.UTC));
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
        if (keyItemRepository.insertWithFingerprintConflictResolve(keyItem, asJson(item.getMeta())) == 1) {
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

    /**
     * The provider's metadata as the column holds it. A native insert binds text, not an entity graph, so the list the
     * entity carries would be dropped silently — {@code key_meta} is written from here or not at all.
     */
    private String asJson(List<MetadataAttribute> meta) {
        if (meta == null || meta.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(meta);
        } catch (JsonProcessingException e) {
            throw new UnusableDiscoveredKeyException("The metadata reported with the key could not be stored.", e);
        }
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

}
