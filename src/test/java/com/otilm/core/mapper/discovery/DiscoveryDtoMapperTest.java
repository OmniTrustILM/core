package com.otilm.core.mapper.discovery;

import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.client.discovery.DiscoveryListDto;
import com.otilm.api.model.client.discovery.DiscoveryWindowMode;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryItemDto;
import com.otilm.api.model.core.discovery.KeyDescriptionDto;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryItemRow;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.CryptographyUtil;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.test.util.ReflectionTestUtils;

import static com.otilm.core.util.TestPublicKeys.dsaPublicKey;
import static com.otilm.core.util.TestPublicKeys.ecPublicKey;
import static com.otilm.core.util.TestPublicKeys.spkiBase64;
import static com.otilm.core.util.builders.DiscoveredKeyDtoBuilder.aPublicKey;
import static com.otilm.core.util.builders.DiscoveredKeyDtoBuilder.aSecretKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;

/**
 * The counts a detail response carries that the run row does not hold: the message count from the message table, the
 * three item counts summed across both staging stores (see {@code DiscoveryDetailCounts}). The mapper takes them from
 * the caller, and they are all longs, so a set handed over in the wrong order would still compile.
 */
class DiscoveryDtoMapperTest {

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

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
    void aV2RunReleasedFromItsDeletedConnectorStillReportsTheItemsItReceived() {
        // A connector's delete clears the interface link of its ended runs; the cursor is what is left to say v2.
        Discovery released = run();
        released.setLastAppliedSequence(40);

        assertThat(DiscoveryDtoMapper
                .toDetailDto(released, new DiscoveryDtoMapper.DetailCounts(0, 0, 0, 0))
                .getItemsDiscovered()).isEqualTo(40);
        assertThat(DiscoveryDtoMapper
                .toDetailDto(run(), new DiscoveryDtoMapper.DetailCounts(0, 0, 0, 0))
                .getItemsDiscovered()).isNull();
    }

    @Test
    void mapsLookbackAndDiscoverSince_whenRunHasLookbackWindow() {
        // given
        var oneDay = Duration.ofDays(1);
        var since = OffsetDateTime.parse("2026-11-17T10:15:30Z");
        Discovery lookback = run();
        lookback.setWindowMode(DiscoveryWindowMode.LOOKBACK);
        lookback.setWindowLookback(oneDay);
        lookback.setDiscoverSince(since);

        // when
        DiscoveryDetailDto dto = DiscoveryDtoMapper.toDetailDto(lookback, noCounts());

        // then
        assertThat(dto.getWindow().getMode()).isEqualTo(DiscoveryWindowMode.LOOKBACK);
        assertThat(dto.getWindow().getLookback()).isEqualTo(oneDay);
        assertThat(dto.getDiscoverSince()).isEqualTo(since);
    }

    @Test
    void mapsModeWithoutLookback_whenRunHasSinceLastSuccessfulRunWindow() {
        // given
        Discovery sinceLastRun = run();
        sinceLastRun.setWindowMode(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN);

        // when
        DiscoveryDetailDto dto = DiscoveryDtoMapper.toDetailDto(sinceLastRun, noCounts());

        // then
        assertThat(dto.getWindow().getMode()).isEqualTo(DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN);
        assertThat(dto.getWindow().getLookback()).isNull();
    }

    @Test
    void omitsWindow_whenRunHasNone() {
        // given
        Discovery withoutWindow = run();

        // when
        DiscoveryDetailDto dto = DiscoveryDtoMapper.toDetailDto(withoutWindow, noCounts());

        // then
        assertThat(dto.getWindow()).isNull();
        assertThat(dto.getDiscoverSince()).isNull();
    }

    @Test
    void reportsTheRecordedMode_whenTheConnectorChoseOne() {
        // given
        Discovery checkpointed = run();
        checkpointed.setConnectorInterfaceUuid(UUID.randomUUID());
        checkpointed.setDeliveryMode(DiscoveryDeliveryMode.CHECKPOINTED);

        // when
        DiscoveryDetailDto dto = DiscoveryDtoMapper.toDetailDto(checkpointed, noCounts());

        // then
        assertThat(dto.getDeliveryMode()).isEqualTo(DiscoveryDeliveryMode.CHECKPOINTED);
    }

    @Test
    void reportsBuffered_whenAV2RunRecordedNoMode() {
        // given
        Discovery neverAnswered = run();
        neverAnswered.setConnectorInterfaceUuid(UUID.randomUUID());

        // when
        DiscoveryDetailDto dto = DiscoveryDtoMapper.toDetailDto(neverAnswered, noCounts());

        // then
        assertThat(dto.getDeliveryMode()).isEqualTo(DiscoveryDeliveryMode.BUFFERED);
    }

    @Test
    void reportsNoMode_whenTheRunIsV1() {
        // given — a run with no connector interface, no stoppable declaration and no drained item
        Discovery v1Run = run();

        // when
        DiscoveryDetailDto dto = DiscoveryDtoMapper.toDetailDto(v1Run, noCounts());

        // then
        assertThat(dto.getDeliveryMode()).isNull();
    }

    @Test
    void theListingCarriesTheItemTotalAndTheResources() {
        Discovery run = run();
        // The database derives it on load; nothing writes it.
        ReflectionTestUtils.setField(run, "totalItemsDiscovered", 52L);
        run.setResources(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));

        DiscoveryListDto dto = DiscoveryDtoMapper.toListDto(run);

        assertThat(dto.getTotalItemsDiscovered()).isEqualTo(52);
        assertThat(dto.getResources()).containsExactly(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY);
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
    void describesAKeyFromItsSpkiAlone_whenALengthStandsBesideIt() throws Exception {
        // given
        var lengthBesideTheSpki = 512;
        var p256 = aPublicKey()
                .withAlgorithm(KeyAlgorithm.ECDSA)
                .withLength(lengthBesideTheSpki)
                .withSpki(spkiBase64(ecPublicKey()))
                .build();

        // when
        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(keyRow(p256));

        // then
        assertThat(dto.getKeyDescription())
                .usingRecursiveComparison()
                .isEqualTo(new KeyDescriptionDto(KeyAlgorithm.ECDSA, "P-256", 256));
    }

    @Test
    void describesAKeyFromItsSpki_whenTheSpkiIsLineWrapped() throws Exception {
        // given
        var lineWrapped = Base64.getMimeEncoder().encodeToString(ecPublicKey().getEncoded());
        var p256 = aPublicKey().withAlgorithm(KeyAlgorithm.ECDSA).withSpki(lineWrapped).build();

        // when
        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(keyRow(p256));

        // then
        assertThat(dto.getKeyDescription())
                .usingRecursiveComparison()
                .isEqualTo(new KeyDescriptionDto(KeyAlgorithm.ECDSA, "P-256", 256));
    }

    @Test
    void sizesAKeyAsTheInventoryDoes_whenTheSpkiHoldsAKeyOutsideCoresTable() throws Exception {
        // given
        var dsa = aPublicKey()
                .withAlgorithm(KeyAlgorithm.UNKNOWN)
                .withLength(null)
                .withSpki(spkiBase64(dsaPublicKey()))
                .build();

        // when
        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(keyRow(dsa));

        // then
        assertThat(dto.getKeyDescription())
                .usingRecursiveComparison()
                .isEqualTo(new KeyDescriptionDto(KeyAlgorithm.UNKNOWN, null, 2048));
    }

    @Test
    void decodesNoPublicKey_whenCoresTableSizesTheSpki() throws Exception {
        // given
        var p256 = aPublicKey().withAlgorithm(KeyAlgorithm.ECDSA).withSpki(spkiBase64(ecPublicKey())).build();
        var row = keyRow(p256);

        try (MockedStatic<CryptographyUtil> cryptography = mockStatic(CryptographyUtil.class, CALLS_REAL_METHODS)) {
            // when
            DiscoveryDtoMapper.toItemDto(row);

            // then
            cryptography.verify(() -> CryptographyUtil.decodePublicKey(any(byte[].class)), never());
        }
    }

    @Test
    void leavesTheLengthOut_whenTheRsaModulusIsZero() throws Exception {
        // given
        var rsaEncryption = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
        var zeroModulus = new SubjectPublicKeyInfo(rsaEncryption,
                new RSAPublicKey(BigInteger.ZERO, BigInteger.valueOf(65537)));
        var key = aPublicKey().withSpki(Base64.getEncoder().encodeToString(zeroModulus.getEncoded())).build();

        // when
        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(keyRow(key));

        // then
        assertThat(dto.getKeyDescription())
                .usingRecursiveComparison()
                .isEqualTo(new KeyDescriptionDto(KeyAlgorithm.RSA, null, null));
    }

    @Test
    void sizesAPrivateKeyAsAPrivateHalf_whenItCarriesAnIdentifier() throws Exception {
        // given
        var privateKey = aPublicKey()
                .withType(KeyType.PRIVATE_KEY)
                .withAlgorithm(KeyAlgorithm.MLDSA)
                .withLength(null)
                .withAlgorithmIdentifier(mlDsa65Identifier())
                .build();

        // when
        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(keyRow(privateKey));

        // then
        assertThat(dto.getKeyDescription())
                .usingRecursiveComparison()
                .isEqualTo(new KeyDescriptionDto(KeyAlgorithm.MLDSA, "ML-DSA-65", 32256));
    }

    @Test
    void describesAKeyByItsIdentifier_whenItStatesAnotherAlgorithm() throws Exception {
        // given
        var statedAsRsa = aPublicKey()
                .withType(KeyType.PRIVATE_KEY)
                .withAlgorithm(KeyAlgorithm.RSA)
                .withAlgorithmIdentifier(mlDsa65Identifier())
                .build();

        // when
        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(keyRow(statedAsRsa));

        // then
        assertThat(dto.getKeyDescription())
                .usingRecursiveComparison()
                .isEqualTo(new KeyDescriptionDto(KeyAlgorithm.MLDSA, "ML-DSA-65", 32256));
    }

    @Test
    void describesTheKeyByItsStatement_whenTheKeyIsSecret() throws Exception {
        // given
        var aes256 = aSecretKey().withAlgorithm(KeyAlgorithm.AES).withLength(256).build();

        // when
        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(keyRow(aes256));

        // then
        assertThat(dto.getKeyDescription())
                .usingRecursiveComparison()
                .isEqualTo(new KeyDescriptionDto(KeyAlgorithm.AES, null, 256));
    }

    @Test
    void listsAKeyWithoutADescription_whenItsSpkiIsUnreadable() throws Exception {
        // given
        var unreadableSpki = Base64.getEncoder().encodeToString("not DER".getBytes(StandardCharsets.US_ASCII));
        var key = aPublicKey().withSpki(unreadableSpki).build();

        // when
        DiscoveryItemDto dto = DiscoveryDtoMapper.toItemDto(keyRow(key));

        // then
        assertThat(dto.getKeyDescription()).isNull();
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

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String mlDsa65Identifier() throws Exception {
        return Base64
                .getEncoder()
                .encodeToString(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_65).getEncoded());
    }

    private static DiscoveryItemRow keyRow(DiscoveredKeyDto key) throws Exception {
        return row("CRYPTOGRAPHIC_KEY", null, null, ObjectMapperFactory.jsonColumn().writeValueAsString(key));
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

            @Override
            public String getProtectedMeta() {
                return null;
            }
        };
    }

    private static DiscoveryDtoMapper.DetailCounts noCounts() {
        return new DiscoveryDtoMapper.DetailCounts(0, 0, 0, 0);
    }

    private static Discovery run() {
        Discovery run = new Discovery();
        run.setUuid(UUID.randomUUID());
        run.setConnectorUuid(UUID.randomUUID());
        return run;
    }
}
