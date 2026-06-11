package com.otilm.core.messaging.model;

import com.otilm.api.model.core.auth.Resource;
import lombok.*;

import java.util.List;
import java.util.UUID;

@Getter
@ToString
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ValidationMessage {

    private Resource resource;

    private List<UUID> uuids;

    private UUID discoveryUuid;
    private String discoveryName;

    private UUID locationUuid;
    private String locationName;
}
