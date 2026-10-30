package com.otilm.core.messaging.model;

import com.otilm.api.model.core.auth.Resource;
import java.util.List;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

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
