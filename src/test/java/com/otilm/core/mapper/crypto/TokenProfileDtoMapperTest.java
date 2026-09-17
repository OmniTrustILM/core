package com.otilm.core.mapper.crypto;

import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileListModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TokenProfileListModel;
import java.util.UUID;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class TokenProfileDtoMapperTest {

    @ParameterizedTest
    @EnumSource(TokenInstanceStatus.class)
    void mapToDto_usesTokenStatusCapturedInSnapshot(TokenInstanceStatus status) {
        // given
        TokenProfile profile = profileWithTokenStatus(status);
        TokenProfileListModel snapshot = ImmutableTokenProfileListModel.from(profile);
        profile.getTokenInstanceReference().setStatus(null);

        // when
        var dto = TokenProfileDtoMapper.mapToDto(snapshot);

        // then
        assertThat(dto.getTokenInstanceStatus()).isEqualTo(status);
    }

    @ParameterizedTest
    @EnumSource(TokenInstanceStatus.class)
    void mapToDetailDto_usesTokenStatusCapturedInSnapshot(TokenInstanceStatus status) {
        // given
        TokenProfile profile = profileWithTokenStatus(status);
        TokenProfileFullModel snapshot = ImmutableTokenProfileFullModel.from(profile);
        profile.getTokenInstanceReference().setStatus(null);

        // when
        var dto = TokenProfileDtoMapper.mapToDetailDto(snapshot);

        // then
        assertThat(dto.getTokenInstanceStatus()).isEqualTo(status);
    }

    private static TokenProfile profileWithTokenStatus(TokenInstanceStatus status) {
        TokenInstanceReference token = new TokenInstanceReference();
        token.setUuid(UUID.randomUUID());
        token.setName("signing-token");
        token.setStatus(status);
        TokenProfile profile = new TokenProfile();
        profile.setUuid(UUID.randomUUID());
        profile.setEnabled(true);
        profile.setTokenInstanceReference(token);
        return profile;
    }
}
