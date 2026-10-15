package com.otilm.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.CryptographicAssetController;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDetailDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetPqcExplanationDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicAssetExternalService;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CryptographicAssetControllerImpl implements CryptographicAssetController {

    private CryptographicAssetExternalService cryptographicAssetService;

    @Autowired
    public void setCryptographicAssetService(CryptographicAssetExternalService cryptographicAssetService) {
        this.cryptographicAssetService = cryptographicAssetService;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CRYPTO_ASSET, operation = Operation.LIST)
    @AuthEndpoint(resourceName = Resource.CRYPTO_ASSET)
    public PaginationResponseDto<CryptographicAssetDto> listCryptographicAssets(SearchRequestDto request) {
        return cryptographicAssetService.listCryptographicAssets(SecurityFilter.create(), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CRYPTO_ASSET, operation = Operation.DETAIL)
    public CryptographicAssetDetailDto getCryptographicAsset(@LogResource(uuid = true) UUID uuid)
            throws NotFoundException {
        return cryptographicAssetService.getCryptographicAsset(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CRYPTO_ASSET, operation = Operation.DETAIL)
    public CryptographicAssetPqcExplanationDto getCryptographicAssetPqcExplanation(@LogResource(uuid = true) UUID uuid)
            throws NotFoundException {
        return cryptographicAssetService.getCryptographicAssetPqcExplanation(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.CRYPTO_ASSET,
            operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return cryptographicAssetService.getSearchableFieldInformationByGroup();
    }
}
