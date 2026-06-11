package com.otilm.core.service.impl;

import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.common.enums.PlatformEnum;
import com.otilm.api.model.core.enums.EnumItemDto;
import com.otilm.core.security.authz.AnyPrincipalEndpoint;
import com.otilm.core.service.EnumExternalService;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Transactional
public class EnumServiceImpl implements EnumExternalService {

    @Override
    @AnyPrincipalEndpoint
    public Map<PlatformEnum, Map<String, EnumItemDto>> getPlatformEnums() {
        Map<PlatformEnum, Map<String, EnumItemDto>> enumsMap = new EnumMap<>(PlatformEnum.class);

        for (PlatformEnum platformEnum: PlatformEnum.values()) {
            Map<String, EnumItemDto> enumItemsMap = new HashMap<>();

            IPlatformEnum[] enumConstants = platformEnum.getEnumClass().getEnumConstants();
            for (IPlatformEnum enumConstant : enumConstants) {
                EnumItemDto enumItem = new EnumItemDto();
                enumItem.setCode(enumConstant.getCode());
                enumItem.setLabel(enumConstant.getLabel());
                enumItem.setDescription(enumConstant.getDescription());
                enumItemsMap.put(enumConstant.getCode(), enumItem);
            }
            enumsMap.put(platformEnum, enumItemsMap);
        }

        return enumsMap;
    }
}
