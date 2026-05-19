package com.czertainly.core.service;

import com.czertainly.api.model.common.enums.PlatformEnum;
import com.czertainly.api.model.core.enums.EnumItemDto;

import java.util.Map;

public interface EnumExternalService {

    /**
     * Get platform enums
     * @return map of platform enums and their items
     */
    Map<PlatformEnum, Map<String, EnumItemDto>> getPlatformEnums();
}
