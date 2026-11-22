package com.otilm.core.model.signing;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures.activeSigningPrivateKey;
import static com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures.publicKey;
import static org.assertj.core.api.Assertions.assertThat;

class SigningKeyItemsTest {

    @Test
    void returnsTheItemFirstInKeyItemOrder_whenItemsAreListedOutOfOrder() {
        // given
        List<CryptographicKeyItemOperationModel> publicKeysInKeyItemOrder = Stream
                .of(publicKey(KeyAlgorithm.RSA), publicKey(KeyAlgorithm.RSA))
                .sorted(Comparator
                        .comparing(CryptographicKeyItemOperationModel::keyItemUuid, SigningCertificate.KEY_ITEM_ORDER))
                .toList();
        CryptographicKeyItemOperationModel firstInKeyItemOrder = publicKeysInKeyItemOrder.getFirst();
        var listedInReverse = List
                .of(activeSigningPrivateKey(KeyAlgorithm.RSA), publicKeysInKeyItemOrder.getLast(), firstInKeyItemOrder);

        // when
        Optional<CryptographicKeyItemOperationModel> selected = SigningKeyItems
                .first(KeyType.PUBLIC_KEY, listedInReverse);

        // then
        assertThat(selected).containsSame(firstInKeyItemOrder);
    }

    @Test
    void returnsNothing_whenNoItemHasTheType() {
        // given
        var onlyPublicKeys = List.of(publicKey(KeyAlgorithm.RSA));

        // when
        Optional<CryptographicKeyItemOperationModel> selected = SigningKeyItems
                .first(KeyType.PRIVATE_KEY, onlyPublicKeys);

        // then
        assertThat(selected).isEmpty();
    }
}
