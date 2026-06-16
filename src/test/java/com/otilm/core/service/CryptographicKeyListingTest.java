package com.otilm.core.service;

import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.cryptography.CryptographicKeyResponseDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyItemDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

/**
 * Guards the list assembly in {@code CryptographicKeyServiceImpl#listCryptographicKeys}.
 *
 * The previous implementation positionally zipped the items list against a separate counts list;
 * any length skew -- a duplicate item row produced by the groups/owner collection fetch, or an
 * item with no association-count row -- overflowed with "Index N out of bounds for length N".
 * The repository is mocked so the skew can be forced directly (real Hibernate de-duplicates the
 * collection fetch, so the skew is not reproducible end-to-end).
 */
class CryptographicKeyListingTest extends BaseSpringBootTest {

    @Autowired
    private CryptographicKeyService cryptographicKeyService;

    @MockitoBean
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    private final UUID itemUuidA = UUID.randomUUID();
    private final UUID itemUuidB = UUID.randomUUID();

    @Test
    void listCryptographicKeys_toleratesCountSkewAndDuplicateItems() {
        CryptographicKeyItem itemA = keyItem(itemUuidA, "keyItemA");
        CryptographicKeyItem itemB = keyItem(itemUuidB, "keyItemB");

        when(cryptographicKeyItemRepository.findUuidsUsingSecurityFilter(any(), any(), any(), any()))
                .thenReturn(List.of(itemUuidA, itemUuidB));
        // findFull returns a duplicate of itemA (as the groups collection fetch does) -- longer than counts.
        when(cryptographicKeyItemRepository.findFullByUuidInOrderByCreatedAtDesc(anyList()))
                .thenReturn(List.of(itemA, itemB, itemA));
        // Only itemA has an association-count row; itemB is absent and must default to 0.
        when(cryptographicKeyItemRepository.getAssociationCounts(anyList()))
                .thenReturn(List.<Object[]>of(new Object[]{itemUuidA, 5L}));
        when(cryptographicKeyItemRepository.countUsingSecurityFilter(any(), any()))
                .thenReturn(2L);

        SearchRequestDto request = new SearchRequestDto();
        request.setItemsPerPage(10);
        request.setPageNumber(1);

        CryptographicKeyResponseDto response =
                cryptographicKeyService.listCryptographicKeys(SecurityFilter.create(), request);

        Assertions.assertNotNull(response);
        // duplicate item row collapsed -> exactly the two distinct items
        Assertions.assertEquals(2, response.getCryptographicKeys().size());
        Assertions.assertEquals(5, byUuid(response, itemUuidA).getAssociations());
        Assertions.assertEquals(0, byUuid(response, itemUuidB).getAssociations());
    }

    private CryptographicKeyItem keyItem(UUID uuid, String name) {
        CryptographicKey parent = new CryptographicKey();
        parent.setUuid(UUID.randomUUID());
        parent.setName(name + "-parent");
        parent.setDescription("desc");

        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setUuid(uuid);
        item.setName(name);
        item.setType(KeyType.PUBLIC_KEY);
        item.setKeyAlgorithm(KeyAlgorithm.RSA);
        item.setState(KeyState.ACTIVE);
        item.setEnabled(true);
        item.setKey(parent);
        return item;
    }

    private static KeyItemDto byUuid(CryptographicKeyResponseDto response, UUID uuid) {
        return response.getCryptographicKeys().stream()
                .filter(dto -> uuid.toString().equals(dto.getUuid()))
                .findFirst()
                .orElseThrow();
    }
}
