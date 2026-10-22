package com.otilm.core.util.builders;

import com.otilm.api.model.connector.cryptography.v2.key.KeyResolutionOutcome;
import com.otilm.api.model.connector.cryptography.v2.key.KeyResolutionV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyPairV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ResolveKeysResponseV2Dto;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds a connector's answer to a key resolution. Each answer takes the identifier of its position, as Core sends each
 * handle under its position.
 */
public final class ResolveKeysResponseV2DtoBuilder {

    private List<KeyResolutionV2Dto> answers = List.of();

    public static ResolveKeysResponseV2DtoBuilder aKeyResolutionResponse() {
        return new ResolveKeysResponseV2DtoBuilder();
    }

    public static KeyResolutionV2Dto found(ListedKeyPairV2Dto keyPair) {
        return new KeyResolutionV2Dto(null, KeyResolutionOutcome.FOUND, keyPair);
    }

    public static KeyResolutionV2Dto answered(KeyResolutionOutcome outcome) {
        return new KeyResolutionV2Dto(null, outcome, null);
    }

    public ResolveKeysResponseV2DtoBuilder withAnswers(KeyResolutionV2Dto... answers) {
        this.answers = List.of(answers);
        return this;
    }

    public ResolveKeysResponseV2Dto build() {
        List<KeyResolutionV2Dto> results = new ArrayList<>();
        for (int position = 0; position < answers.size(); position++) {
            KeyResolutionV2Dto answer = answers.get(position);
            results.add(new KeyResolutionV2Dto(Integer.toString(position), answer.getOutcome(), answer.getKey()));
        }
        return new ResolveKeysResponseV2Dto(results);
    }
}
