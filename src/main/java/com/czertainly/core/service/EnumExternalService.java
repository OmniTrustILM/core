package com.czertainly.core.service;

import com.otilm.api.model.common.enums.PlatformEnum;
import com.otilm.api.model.core.enums.EnumItemDto;

import java.util.Map;

public interface EnumExternalService {

    /**
     * Get platform enums
     * @return map of platform enums and their items
     */
    Map<PlatformEnum, Map<String, EnumItemDto>> getPlatformEnums();
}
