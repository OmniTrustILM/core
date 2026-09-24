package com.otilm.core.mapper.discovery;

import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryItemDto;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryItemRow;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.util.CertificateUtil;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.DiscoveredKeyDtoBuilder.aPublicKey;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The counts a detail response carries that the run row does not hold: the message count from the message table, the
 * three item counts summed across both staging stores (see {@code DiscoveryDetailCounts}). The mapper takes them from
 * the caller, and they are all longs, so a set handed over in the wrong order would still compile.
 */
class DiscoveryDtoMapperTest {

    @Test
    void everyCountLandsOnTheFieldThatNamesIt() {
        DiscoveryDetailDto dto = DiscoveryDtoMapper
                .toDetailDto(run(), new DiscoveryDtoMapper.DetailCounts(3, 11, 7, 2));

        assertThat(dto.getRunMessageCount()).isEqualTo(3);
        assertThat(dto.getItemsNewlyDiscovered()).isEqualTo(11);
        assertThat(dto.getItemsProcessed()).isEqualTo(7);
        assertThat(dto.getItemsFailed()).isEqualTo(2);
    }

    @Test
    void aRunThatFoundOnlyKnownItems_reportsNoneNewRatherThanNothingAtAll() {
        DiscoveryDetailDto dto = DiscoveryDtoMapper.toDetailDto(run(), new DiscoveryDtoMapper.DetailCounts(0, 0, 0, 0));

        // A re-scan of a known host stages items and adds none. The field is primitive and REQUIRED precisely so
        // that answer is on the wire as 0, rather than absent and read as "not reported".
        assertThat(dto.getItemsNewlyDiscovered()).isZero();
        assertThat(dto.getItemsProcessed()).isZero();
        assertThat(dto.getItemsFailed()).isZero();
    }

    @Test
    void anImportedItemPointsAtTheObjectWithTheResourceItBelongsTo() {
        UUID keyUuid = UUID.randomUUID();

        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(row("CRYPTOGRAPHIC_KEY", keyUuid, "discovered_key-a"));

        // The resource comes off the staged row, not the payload, so this row answers for it while carrying none.
        assertThat(dto.getResource()).isEqualTo(Resource.CRYPTOGRAPHIC_KEY);
        assertThat(dto.getInventory().getUuid()).isEqualTo(keyUuid.toString());
        assertThat(dto.getInventory().getName()).isEqualTo("discovered_key-a");
    }

    @Test
    void aStoredKeyPayload_decodesAsTheKeyItWas() throws Exception {
        String payload = ObjectMapperFactory.jsonColumn().writeValueAsString(aPublicKey().build());

        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(row("CRYPTOGRAPHIC_KEY", null, null, payload));

        assertThat(dto.getPayload()).isInstanceOf(DiscoveredKeyDto.class);
    }

    @Test
    void anObjectWithNoNameOfItsOwnReadsAsTheCertificateListingReadsIt() {
        // A certificate with no common name -- a SAN-only one -- has nothing to be called, and the certificate
        // listing already answers that with a placeholder. Two listings of the same object must not disagree.
        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(row("CERTIFICATE", UUID.randomUUID(), null));

        assertThat(dto.getInventory().getName()).isEqualTo(CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER);
    }

    @Test
    void anItemThatBecameNothingCarriesNoReferenceAtAll() {
        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(row("CRYPTOGRAPHIC_KEY", null, null));

        assertThat(dto.getInventory()).isNull();
    }

    private static DiscoveryItemRow row(String resource, UUID inventoryUuid, String inventoryName) {
        return row(resource, inventoryUuid, inventoryName, null);
    }

    private static DiscoveryItemRow row(String resource, UUID inventoryUuid, String inventoryName, String payload) {
        return new DiscoveryItemRow() {

            @Override
            public UUID getUuid() {
                return UUID.randomUUID();
            }

            @Override
            public UUID getInventoryUuid() {
                return inventoryUuid;
            }

            @Override
            public String getInventoryName() {
                return inventoryName;
            }

            @Override
            public long getSequence() {
                return 1L;
            }

            @Override
            public String getUniqueRef() {
                return "ref-1";
            }

            @Override
            public String getResource() {
                return resource;
            }

            @Override
            public Instant getDiscoveredAt() {
                return null;
            }

            @Override
            public String getPayload() {
                return payload;
            }

            @Override
            public boolean isNewlyDiscovered() {
                return true;
            }

            @Override
            public boolean isProcessed() {
                return inventoryUuid != null;
            }

            @Override
            public String getProcessedError() {
                return null;
            }

            @Override
            public String getMeta() {
                return null;
            }
        };
    }

    private static Discovery run() {
        Discovery run = new Discovery();
        run.setUuid(UUID.randomUUID());
        run.setConnectorUuid(UUID.randomUUID());
        return run;
    }
}
