package com.otilm.core.mapper.crypto;

import com.otilm.api.model.client.cryptography.CryptographicKeyResponseDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.cryptography.key.KeyAssociationDto;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDto;
import com.otilm.core.mapper.workflows.PaginationResponseMapper;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyListModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyListModel;
import com.otilm.core.model.crypto.KeyCertificateAssociationModel;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.group.GroupModel;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.data.domain.Page;

public final class CryptographicKeyDtoMapper {

    private static final String PROVIDER_MANAGED_KEY_DATA = "Key material is managed by the cryptography provider and is not available in Core.";

    private CryptographicKeyDtoMapper() {
    }

    /** Adapts the shared pagination mapping to the key listing's dedicated response format. */
    public static CryptographicKeyResponseDto mapToResponseDto(Page<?> page, List<KeyItemDto> items) {
        PaginationResponseDto<KeyItemDto> pagination = PaginationResponseMapper.toDto(page, items);
        CryptographicKeyResponseDto dto = new CryptographicKeyResponseDto();
        dto.setCryptographicKeys(pagination.getItems());
        dto.setItemsPerPage(pagination.getItemsPerPage());
        dto.setPageNumber(pagination.getPageNumber());
        dto.setTotalItems(pagination.getTotalItems());
        dto.setTotalPages(pagination.getTotalPages());
        return dto;
    }

    public static List<KeyItemDetailDto> getKeyItems(CryptographicKeyFullModel key) {
        return key.items().stream().map(CryptographicKeyDtoMapper::mapItemToDetailDto).toList();
    }

    public static List<KeyItemDto> getKeyItemsSummary(CryptographicKeyListModel key) {
        return key.items().stream().map(item -> mapItemToSummaryDto(item, key)).toList();
    }

    public static List<KeyItemDto> getKeyItemsSummary(CryptographicKeyFullModel key) {
        return getKeyItemsSummary(summaryOf(key, 0));
    }

    public static KeyDto mapToDto(CryptographicKeyFullModel key) {
        int associationCount = key.items().size() - 1 + key.certificateAssociations().size();
        return mapToDto(summaryOf(key, associationCount));
    }

    public static KeyDto mapToDto(CryptographicKeyListModel key) {
        KeyDto dto = buildKeyDto(key);
        dto.setAssociations(key.associationCount());
        return dto;
    }

    /** Omits association counts so chain responses do not initialize certificate collections. */
    public static KeyDto mapToChainDto(CryptographicKeyFullModel key) {
        return mapToChainDto(summaryOf(key, 0));
    }

    public static KeyDto mapToChainDto(CryptographicKeyListModel key) {
        return buildKeyDto(key);
    }

    private static CryptographicKeyListModel summaryOf(CryptographicKeyFullModel key, int associationCount) {
        String profileName = key.tokenProfile() == null ? null : key.tokenProfile().name();
        String tokenName = key.tokenInstance() == null ? null : key.tokenInstance().name();
        return new ImmutableCryptographicKeyListModel(key.uuid(), key.name(), key.description(), key.tokenProfileUuid(),
                key.tokenInstanceReferenceUuid(), key.groups(), profileName, tokenName, key.created(), key.ownerUuid(),
                key.ownerName(), key.items(), associationCount);
    }

    /**
     * Populates a {@link KeyDto} with all fields except {@code associations}.
     */
    private static KeyDto buildKeyDto(CryptographicKeyListModel key) {
        KeyDto dto = new KeyDto();
        dto.setName(key.name());
        dto.setUuid(key.uuid().toString());
        dto.setDescription(key.description());
        dto.setCreationTime(key.created());
        if (key.tokenProfileUuid() != null) {
            dto.setTokenProfileName(key.tokenProfileName());
            dto.setTokenProfileUuid(key.tokenProfileUuid().toString());
        }
        if (key.tokenInstanceReferenceUuid() != null) {
            dto.setTokenInstanceName(key.tokenInstanceName());
            dto.setTokenInstanceUuid(key.tokenInstanceReferenceUuid().toString());
        }
        if (key.groups() != null) {
            dto.setGroups(key.groups().stream().map(CryptographicKeyDtoMapper::mapGroup).toList());
        }
        if (key.ownerUuid() != null) {
            dto.setOwnerUuid(key.ownerUuid().toString());
            dto.setOwner(key.ownerName());
        }
        dto.setItems(getKeyItemsSummary(key));
        dto.setComplianceStatus(getComplianceStatus(key.items()));
        return dto;
    }

    private static ComplianceStatus getComplianceStatus(List<CryptographicKeyItemBasicModel> items) {
        if (items.isEmpty()) {
            return ComplianceStatus.NOT_CHECKED;
        }
        List<ComplianceStatus> statuses = items
                .stream()
                .map(CryptographicKeyItemBasicModel::complianceStatus)
                .filter(Objects::nonNull)
                .toList();
        if (statuses.isEmpty()) {
            return ComplianceStatus.NOT_CHECKED;
        }
        if (statuses.contains(ComplianceStatus.NOK)) {
            return ComplianceStatus.NOK;
        } else if (statuses.contains(ComplianceStatus.FAILED)) {
            return ComplianceStatus.FAILED;
        } else if (statuses.contains(ComplianceStatus.NA)) {
            return ComplianceStatus.NA;
        } else if (statuses.contains(ComplianceStatus.NOT_CHECKED)) {
            return ComplianceStatus.NOT_CHECKED;
        } else {
            return ComplianceStatus.OK;
        }
    }

    public static KeyDetailDto mapToDetailDto(CryptographicKeyFullModel key) {
        KeyDetailDto dto = new KeyDetailDto();
        dto.setName(key.name());
        dto.setUuid(key.uuid().toString());
        dto.setDescription(key.description());
        dto.setCreationTime(key.created());
        dto.setComplianceStatus(getComplianceStatus(key.items()));
        if (key.tokenProfile() != null) {
            dto.setTokenProfileName(key.tokenProfile().name());
            dto.setTokenProfileUuid(key.tokenProfile().uuid().toString());
        }
        if (key.tokenInstance() != null) {
            dto.setTokenInstanceName(key.tokenInstance().name());
            dto.setTokenInstanceUuid(key.tokenInstanceReferenceUuid().toString());
        }
        dto.setItems(getKeyItems(key));
        if (key.groups() != null) {
            dto.setGroups(key.groups().stream().map(CryptographicKeyDtoMapper::mapGroup).toList());
        }
        if (key.ownerUuid() != null) {
            dto.setOwnerUuid(key.ownerUuid().toString());
            dto.setOwner(key.ownerName());
        }
        List<KeyAssociationDto> keyAssociationDtos = key
                .certificateAssociations()
                .stream()
                .map(CryptographicKeyDtoMapper::mapCertificateAssociation)
                .toList();
        dto.setAssociations(keyAssociationDtos);
        return dto;
    }

    /**
     * Maps a key-item snapshot to its detail response.
     *
     * @param item non-null key-item snapshot
     * @return item details without separately loaded attributes or metadata
     */
    public static KeyItemDetailDto mapItemToDetailDto(CryptographicKeyItemBasicModel item) {
        KeyItemDetailDto dto = new KeyItemDetailDto();
        dto.setUuid(item.uuid().toString());
        dto.setName(item.name());
        if (item.reference() instanceof RemoteKeyReference.UuidReference(UUID uuid) && uuid != null) {
            dto.setKeyReferenceUuid(uuid.toString());
        }
        dto.setKeyAlgorithm(item.algorithm());
        dto.setType(item.type());
        dto.setLength(item.length());
        dto.setFormat(responseFormat(item));
        dto.setState(item.state());
        dto.setEnabled(item.enabled());
        dto.setUsage(item.usages());
        dto.setReason(item.reason());
        dto.setKeyData(item.keyData() == null ? PROVIDER_MANAGED_KEY_DATA : item.keyData());
        dto.setComplianceStatus(item.complianceStatus());
        dto.setExportable(item.exportable());
        return dto;
    }

    private static KeyItemDto mapItemToSummaryDto(CryptographicKeyItemBasicModel item, CryptographicKeyListModel key) {
        KeyItemDto dto = new KeyItemDto();
        dto.setUuid(item.uuid().toString());
        dto.setName(item.name());
        if (item.reference() instanceof RemoteKeyReference.UuidReference(UUID uuid) && uuid != null) {
            dto.setKeyReferenceUuid(uuid.toString());
        }
        dto.setKeyAlgorithm(item.algorithm());
        dto.setType(item.type());
        dto.setLength(item.length());
        dto.setFormat(responseFormat(item));
        dto.setState(item.state());
        dto.setEnabled(item.enabled());
        dto.setUsage(item.usages());
        dto.setComplianceStatus(item.complianceStatus());
        dto.setKeyWrapperUuid(key.uuid().toString());
        dto.setDescription(key.description());
        dto.setCreationTime(key.created());
        List<GroupDto> groups = key.groups().stream().map(CryptographicKeyDtoMapper::mapGroup).toList();
        dto.setGroups(groups);
        if (key.ownerUuid() != null) {
            dto.setOwnerUuid(key.ownerUuid().toString());
            dto.setOwner(key.ownerName());
        }
        if (key.tokenProfileUuid() != null) {
            dto.setTokenProfileUuid(key.tokenProfileUuid().toString());
            dto.setTokenProfileName(key.tokenProfileName());
        }
        if (key.tokenInstanceReferenceUuid() != null) {
            dto.setTokenInstanceUuid(key.tokenInstanceReferenceUuid().toString());
            dto.setTokenInstanceName(key.tokenInstanceName());
        }
        return dto;
    }

    /** Uses a custom display value when Core has no encoded key material. */
    private static KeyFormat responseFormat(CryptographicKeyItemBasicModel item) {
        return item.keyData() == null ? KeyFormat.CUSTOM : item.format();
    }

    private static GroupDto mapGroup(GroupModel group) {
        GroupDto dto = new GroupDto();
        dto.setUuid(group.uuid().toString());
        dto.setName(group.name());
        dto.setDescription(group.description());
        dto.setEmail(group.email());
        return dto;
    }

    private static KeyAssociationDto mapCertificateAssociation(KeyCertificateAssociationModel certificate) {
        KeyAssociationDto dto = new KeyAssociationDto();
        dto.setUuid(certificate.uuid().toString());
        dto.setName(certificate.name());
        dto.setResource(Resource.CERTIFICATE);
        return dto;
    }
}
