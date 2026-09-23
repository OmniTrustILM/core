package com.otilm.core.service.writer.discovery;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.util.KeySizeUtil;
import java.security.PublicKey;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Files a discovered public key in the inventory and stamps the staged row that produced it.
 *
 * <p>
 * Both entry points are one item's unit of work, and the caller runs each in its own transaction: one key that cannot
 * be written must not take the batch's other keys with it, and the stamp has to survive whatever the caller does next.
 * The boundary is the caller's because a writer holds @Modifying calls, which need an ambient transaction rather than
 * one they open themselves.
 */
@Service
public class DiscoveredKeyWriter {

    private final CryptographicKeyItemRepository keyItemRepository;
    private final DiscoveryItemRepository itemRepository;
    private final CertificateKeyWriter publicKeyWriter;

    public DiscoveredKeyWriter(CryptographicKeyItemRepository keyItemRepository, DiscoveryItemRepository itemRepository,
            CertificateKeyWriter publicKeyWriter) {
        this.keyItemRepository = keyItemRepository;
        this.itemRepository = itemRepository;
        this.publicKeyWriter = publicKeyWriter;
    }

    /**
     * Files the public key under the record that already holds it, or a new one, and stamps the item with that record.
     * A new record is written by the insert a certificate's public key goes through, so a key discovered on its own and
     * the same key inside a certificate get one record, the same attributes and the same handling of a concurrent
     * import.
     *
     * @return the key record the item became
     */
    @Transactional
    public UUID importKey(DiscoveryItem item, PublicKey publicKey, String fingerprint) {
        UUID keyUuid = keyItemRepository
                .findByFingerprint(fingerprint)
                .map(CryptographicKeyItem::getKeyUuid)
                .orElseGet(() -> publicKeyWriter
                        .uploadCertificatePublicKey(nameFor(item, fingerprint), publicKey,
                                KeySizeUtil.getKeyLength(publicKey), fingerprint));
        itemRepository.markImported(item.getUuid(), keyUuid, OffsetDateTime.now(ZoneOffset.UTC));
        return keyUuid;
    }

    @Transactional
    public void markFailed(UUID itemUuid, String reason) {
        itemRepository.markFailed(itemUuid, reason, OffsetDateTime.now(ZoneOffset.UTC));
    }

    /**
     * Gives every key row the run never reached a reason, so the listing says why they stayed out instead of showing
     * them waiting on a run that has ended.
     *
     * @return how many rows were stamped
     */
    @Transactional
    public int markUnreachedKeys(UUID discoveryUuid, String reason) {
        return itemRepository
                .markPendingNotImported(discoveryUuid, Resource.CRYPTOGRAPHIC_KEY.name(), reason,
                        OffsetDateTime.now(ZoneOffset.UTC));
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
