package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyType;
import java.util.List;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.ProviderKeyPairBuilder.aProviderKeyPair;
import static org.assertj.core.api.Assertions.assertThat;

class ProviderKeyPairTest {

    @Test
    void namesEachOnboardedItemAfterTheKey() {
        // given
        ProviderKeyPair pair = aProviderKeyPair().build();

        // when
        List<ProviderKeyItem> items = pair.toOnboardedItems("signer");

        // then
        assertThat(items).extracting(ProviderKeyItem::name).containsExactly("signer public key", "signer private key");
        assertThat(items).extracting(ProviderKeyItem::type).containsExactly(KeyType.PUBLIC_KEY, KeyType.PRIVATE_KEY);
    }

    @Test
    void onboardsThePrivateKeyAlone_whenTheTokenHoldsNoPublicKey() {
        // given
        ProviderKeyPair privateKeyAlone = aProviderKeyPair().withoutPublicKey().build();

        // when
        List<ProviderKeyItem> items = privateKeyAlone.toOnboardedItems("signer");

        // then
        assertThat(items).singleElement().satisfies(item -> {
            assertThat(item.name()).isEqualTo("signer private key");
            assertThat(item.type()).isEqualTo(KeyType.PRIVATE_KEY);
        });
    }
}
