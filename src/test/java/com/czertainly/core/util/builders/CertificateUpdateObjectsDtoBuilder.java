package com.czertainly.core.util.builders;

import com.otilm.api.model.client.certificate.CertificateUpdateObjectsDto;

import java.util.List;

public class CertificateUpdateObjectsDtoBuilder {

    private List<String> groupUuids = null;
    private String ownerUuid = null;
    private String raProfileUuid = null;
    private Boolean trustedCa = null;

    public static CertificateUpdateObjectsDtoBuilder aCertificateUpdateObjectsRequest() {
        return new CertificateUpdateObjectsDtoBuilder();
    }

    public CertificateUpdateObjectsDtoBuilder withGroupUuids(List<String> groupUuids) {
        this.groupUuids = groupUuids;
        return this;
    }

    public CertificateUpdateObjectsDtoBuilder withOwnerUuid(String ownerUuid) {
        this.ownerUuid = ownerUuid;
        return this;
    }

    public CertificateUpdateObjectsDtoBuilder withRaProfileUuid(String raProfileUuid) {
        this.raProfileUuid = raProfileUuid;
        return this;
    }

    public CertificateUpdateObjectsDtoBuilder withTrustedCa(Boolean trustedCa) {
        this.trustedCa = trustedCa;
        return this;
    }

    public CertificateUpdateObjectsDto build() {
        CertificateUpdateObjectsDto dto = new CertificateUpdateObjectsDto();
        dto.setGroupUuids(groupUuids);
        dto.setOwnerUuid(ownerUuid);
        dto.setRaProfileUuid(raProfileUuid);
        dto.setTrustedCa(trustedCa);
        return dto;
    }
}
