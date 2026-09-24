package com.otilm.core.service.writer.discovery;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.util.KeySizeUtil;
import java.security.PublicKey;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Files a discovered public key in the inventory and stamps the staged row that produced it.
 *
 * <p>
 * Each method is one item's unit of work, which the caller runs in its own transaction: one key cannot take the batch's
 * other keys with it, and a stamp survives whatever the caller does next. Writer methods join the caller's transaction
 * because their @Modifying calls need an ambient one.
 */
@Service
public class DiscoveredKeyWriter {

    private final CryptographicKeyItemRepository keyItemRepository;
    private final DiscoveryItemRepository itemRepository;
    private final CertificateKeyWriter publicKeyWriter;
    private final CertificateInternalService certificateService;

    public DiscoveredKeyWriter(CryptographicKeyItemRepository keyItemRepository, DiscoveryItemRepository itemRepository,
            CertificateKeyWriter publicKeyWriter, @Lazy CertificateInternalService certificateService) {
        this.keyItemRepository = keyItemRepository;
        this.itemRepository = itemRepository;
        this.publicKeyWriter = publicKeyWriter;
        this.certificateService = certificateService;
    }

    /**
     * Claims the item, files the public key under the record that already holds it or a new one written by the
     * certificate public-key insert, and stamps the item with that record. The claim comes first so a tick that lost
     * the row to another one, or to the run's ending, touches nothing.
     *
     * @return the key item the public key is filed as, or empty when the item was no longer pending
     */
    @Transactional
    public Optional<UUID> importKey(DiscoveryItem item, PublicKey publicKey, String fingerprint) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        if (itemRepository.claimPending(item.getUuid(), now) == 0) {
            return Optional.empty();
        }
        CryptographicKeyItem keyItem = keyItemRepository
                .findByFingerprint(fingerprint)
                .orElseGet(() -> fileNewKey(item, publicKey, fingerprint));
        itemRepository.markImported(item.getUuid(), keyItem.getKeyUuid(), now);
        return Optional.of(keyItem.getUuid());
    }

    /**
     * Writes the record and points the certificates carrying this key at it, as a token's newly created public key
     * does. A certificate can hold the key's fingerprint and no key record: deleting a key leaves it that way.
     */
    private CryptographicKeyItem fileNewKey(DiscoveryItem item, PublicKey publicKey, String fingerprint) {
        UUID keyUuid = publicKeyWriter
                .uploadCertificatePublicKey(nameFor(item, fingerprint), publicKey, KeySizeUtil.getKeyLength(publicKey),
                        fingerprint);
        certificateService.updateCertificateKeys(keyUuid, fingerprint);
        return keyItemRepository
                .findByFingerprint(fingerprint)
                .orElseThrow(() -> new IllegalStateException("A public key just filed could not be read back"));
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
