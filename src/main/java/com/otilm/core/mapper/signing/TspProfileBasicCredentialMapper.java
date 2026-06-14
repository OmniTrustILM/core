package com.otilm.core.mapper.signing;

import com.otilm.api.model.client.signing.protocols.tsp.TspBasicCredentialDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;

public class TspProfileBasicCredentialMapper {
    private TspProfileBasicCredentialMapper() {
    }

    public static TspBasicCredentialDto mapToDto(TspProfileBasicCredential credential, String mappedUserName) {
        TspBasicCredentialDto dto = new TspBasicCredentialDto();
        dto.setUuid(credential.getUuid());
        dto.setUsername(credential.getUsername());
        NameAndUuidDto mapped = new NameAndUuidDto();
        mapped.setUuid(credential.getMappedUserUuid().toString());
        mapped.setName(mappedUserName);
        dto.setMappedUser(mapped);
        return dto;
    }
}
