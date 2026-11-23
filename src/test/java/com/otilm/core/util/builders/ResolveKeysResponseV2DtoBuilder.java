package com.otilm.core.util.builders;

import com.otilm.api.model.connector.cryptography.v2.key.KeyEntryStatus;
import com.otilm.api.model.connector.cryptography.v2.key.KeyResolutionV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyEntryV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ResolveKeysResponseV2Dto;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds a connector's answer to a key resolution. Each answer takes the identifier of its position, as Core sends each
 * handle under its position.
 */
public final class ResolveKeysResponseV2DtoBuilder {

    private List<ListedKeyEntryV2Dto> answers = List.of();

    public static ResolveKeysResponseV2DtoBuilder aKeyResolutionResponse() {
        return new ResolveKeysResponseV2DtoBuilder();
    }

    public static ListedKeyEntryV2Dto answered(KeyEntryStatus status) {
        ListedKeyEntryV2Dto answer = new ListedKeyEntryV2Dto();
        answer.setStatus(status);
        return answer;
    }

    public ResolveKeysResponseV2DtoBuilder withAnswers(ListedKeyEntryV2Dto... answers) {
        this.answers = List.of(answers);
        return this;
    }

    public ResolveKeysResponseV2Dto build() {
        List<KeyResolutionV2Dto> results = new ArrayList<>();
        for (int position = 0; position < answers.size(); position++) {
            results.add(resolution(Integer.toString(position), answers.get(position)));
        }
        return new ResolveKeysResponseV2Dto(results);
    }

    private static KeyResolutionV2Dto resolution(String identifier, ListedKeyEntryV2Dto answer) {
        KeyResolutionV2Dto result = new KeyResolutionV2Dto();
        result.setIdentifier(identifier);
        result.setStatus(answer.getStatus());
        result.setDiagnostic(answer.getDiagnostic());
        result.setStorageName(answer.getStorageName());
        result.setKey(answer.getKey());
        result.setKeyData(answer.getKeyData());
        return result;
    }
}
