package com.otilm.core.util.builders;

import com.otilm.api.model.client.cryptography.tokenprofile.AddTokenProfileRequestDto;
import com.otilm.api.model.core.cryptography.key.KeyUsage;

import java.util.List;

public class TokenProfileRequestDtoBuilder {

    private String name = "test-token-profile";
    private boolean enabled = true;
    private List<KeyUsage> usage = List.of(KeyUsage.SIGN, KeyUsage.VERIFY);

    public static TokenProfileRequestDtoBuilder aTokenProfileRequest() {
        return new TokenProfileRequestDtoBuilder();
    }

    public TokenProfileRequestDtoBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public TokenProfileRequestDtoBuilder enabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public TokenProfileRequestDtoBuilder withUsage(KeyUsage... usage) {
        this.usage = List.of(usage);
        return this;
    }

    public AddTokenProfileRequestDto build() {
        AddTokenProfileRequestDto dto = new AddTokenProfileRequestDto();
        dto.setName(name);
        dto.setEnabled(enabled);
        dto.setAttributes(List.of());
        dto.setCustomAttributes(List.of());
        dto.setUsage(usage);
        return dto;
    }
}
