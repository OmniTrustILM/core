package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.event.DiscoveryResultBatchEvent;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.model.discovery.DiscoveryMessageDraft;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.service.writer.discovery.DiscoveryItemWriter;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import jakarta.validation.Validation;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The ingestor decisions a database test cannot pin down: what happens to work addressed to a run that no longer
 * exists, and how a key's inventory correlation is resolved before it is staged.
 */
@ExtendWith(MockitoExtension.class)
class DiscoveryEventIngestorTest {

    private static final String SPKI = Base64.getEncoder().encodeToString(rsaPublicKey().getEncoded());

    @Mock
    private DiscoveryRepository discoveryRepository;
    @Mock
    private DiscoveryItemWriter itemWriter;
    @Mock
    private DiscoveryWorkWriter workWriter;
    @Mock
    private CertificateHandler certificateHandler;
    @Mock
    private CryptographicKeyItemRepository keyItemRepository;
    @Mock
    private DiscoveryCertificateRepository certificateRepository;
    @Mock
    private DiscoveryMessageWriter messageWriter;

    private DiscoveryEventIngestor ingestor;

    @BeforeEach
    void setUp() {
        ingestor = new DiscoveryEventIngestor(discoveryRepository, itemWriter, workWriter, certificateHandler,
                keyItemRepository, certificateRepository, messageWriter,
                Validation.buildDefaultValidatorFactory().getValidator());
    }

    @Test
    void pageForADeletedRun_isDroppedRatherThanFailing() {
        UUID gone = UUID.randomUUID();
        when(discoveryRepository.findWithLockByUuid(gone)).thenReturn(Optional.empty());

        // The agenda row cascaded away with the run, so this is a redelivered obsolete tick, not a fault:
        // throwing would send it round the broker's redelivery loop forever.
        ingestor.applyDrainPage(gone, page(keyItem(1, "key-a", "fp-a")));

        verifyNoInteractions(itemWriter, certificateHandler);
    }

    @Test
    void advisoryEventForADeletedRun_isDroppedRatherThanFailing() {
        UUID gone = UUID.randomUUID();
        when(discoveryRepository.findWithLockByUuid(gone)).thenReturn(Optional.empty());

        ingestor.applyAdvisoryEvent(gone, new DiscoveryResultBatchEvent());

        verifyNoInteractions(workWriter);
    }

    @Test
    void keyAlreadyInInventory_isStagedAsNotNewlyDiscovered() {
        Discovery run = run();
        DiscoveredItemDto known = keyItem(1, "key-a", SPKI);
        String identity = DiscoveredKeyIdentity.of((DiscoveredKeyDto) known.getPayload());
        when(keyItemRepository.findKnownFingerprints(Set.of(identity))).thenReturn(List.of(identity));

        ingestor.applyDrainPage(run.getUuid(), page(known));

        verify(itemWriter).stage(eq(run.getUuid()), any(DiscoveredItemDto.class), eq(false));
    }

    @Test
    void keyMissingFromInventory_isStagedAsNewlyDiscovered() {
        Discovery run = run();
        when(keyItemRepository.findKnownFingerprints(any())).thenReturn(List.of());

        ingestor.applyDrainPage(run.getUuid(), page(keyItem(1, "key-a", SPKI)));

        verify(itemWriter).stage(eq(run.getUuid()), any(DiscoveredItemDto.class), eq(true));
    }

    @Test
    void keyWithoutAPublicPart_isStagedAsNewlyDiscoveredWithoutAnInventoryLookup() {
        Discovery run = run();

        ingestor.applyDrainPage(run.getUuid(), page(keyItem(1, "key-a", null)));

        verify(keyItemRepository, never()).findKnownFingerprints(any());
        verify(itemWriter).stage(eq(run.getUuid()), any(DiscoveredItemDto.class), eq(true));
    }

    /**
     * The wire contract is enforced only where a Validator runs, and the REST and MQ clients deserialize without one,
     * so the ingestor is the last point before a row exists where a private key a connector must never have sent can be
     * stopped.
     */
    @Test
    void anItemBreakingTheContract_isSkippedWithAMessageRatherThanStaged() {
        Discovery run = run();
        DiscoveredItemDto leaked = keyItem(1, "key-a", "fp-a");
        DiscoveredKeyDto payload = (DiscoveredKeyDto) leaked.getPayload();
        payload.setType(KeyType.PRIVATE_KEY);
        payload.setPublicKeyFormat(KeyFormat.PRKI);
        payload.setPublicKey("MIIBOgIBAAJBAK...");

        boolean advanced = ingestor.applyDrainPage(run.getUuid(), page(leaked));

        verify(itemWriter, never()).stage(any(), any(), anyBoolean());
        ArgumentCaptor<List<DiscoveryMessageDraft>> filed = ArgumentCaptor.captor();
        verify(messageWriter, atLeastOnce()).appendAll(eq(run.getUuid()), filed.capture());
        assertThat(filed.getAllValues().stream().flatMap(List::stream))
                .extracting(DiscoveryMessageDraft::code)
                .contains(DiscoveryMessageCode.ITEM_INVALID.code());
        assertThat(advanced).as("re-sending the same item cannot make it valid, so the cursor steps over it").isTrue();
    }

    private Discovery run() {
        Discovery run = new Discovery();
        run.setUuid(UUID.randomUUID());
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        when(discoveryRepository.findWithLockByUuid(run.getUuid())).thenReturn(Optional.of(run));
        return run;
    }

    private DiscoveryResultsResponseDto page(DiscoveredItemDto... items) {
        DiscoveryResultsResponseDto page = new DiscoveryResultsResponseDto();
        page.setItems(List.of(items));
        page.setHighestSequence(1L);
        page.setMore(false);
        return page;
    }

    /**
     * A key with public material, or with none when {@code publicKey} is null: only material gives Core an identity.
     */
    private DiscoveredItemDto keyItem(long sequence, String uniqueRef, String publicKey) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.PUBLIC_KEY);
        payload.setAlgorithm(KeyAlgorithm.RSA);
        payload.setFingerprint("whatever-the-connector-computed");
        if (publicKey != null) {
            payload.setPublicKeyFormat(KeyFormat.SPKI);
            payload.setPublicKey(publicKey);
        }
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(sequence);
        item.setUniqueRef(uniqueRef);
        item.setPayload(payload);
        return item;
    }

    private static PublicKey rsaPublicKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair().getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
