package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KeyOperationScopeTest {

    @Test
    void tokenProfile_buildsBasicModel_withUsagesFromBitmask() {
        // given
        UUID profileUuid = UUID.randomUUID();
        UUID tokenUuid = UUID.randomUUID();
        int usage = BitMaskEnum.convertSetToBitMask(EnumSet.of(KeyUsage.SIGN));
        KeyOperationScope scope = new KeyOperationScope(profileUuid, "profile", "desc", "token", tokenUuid, true,
                usage);

        // when
        TokenProfileBasicModel profile = scope.tokenProfile();

        // then
        assertEquals(profileUuid, profile.uuid());
        assertEquals("profile", profile.name());
        assertEquals(tokenUuid, profile.tokenInstanceReferenceUuid());
        assertEquals(List.of(KeyUsage.SIGN), profile.usages());
    }
}
