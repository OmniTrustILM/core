package com.otilm.core.service.v2;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.ConnectRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInfo;
import com.otilm.api.model.client.connector.v2.HealthInfo;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.connector.v2.ConnectInfo;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.connector.v2.ConnectorDto;
import com.otilm.api.model.core.connector.v2.ConnectorRequestDto;
import com.otilm.api.model.core.connector.v2.ConnectorUpdateRequestDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.model.connector.ImmutableConnectorBasicModel;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import java.util.List;

public interface ConnectorExternalService {

    ImmutableConnectorFullModel getConnectorFullModel(SecuredUUID uuid) throws NotFoundException;

    ImmutableConnectorBasicModel getConnectorBasicModel(SecuredUUID uuid) throws NotFoundException;

    PaginationResponseDto<ConnectorDto> listConnectors(SecurityFilter filter, SearchRequestDto request);

    ConnectorDetailDto getConnector(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    ConnectorDetailDto createConnector(ConnectorRequestDto request)
            throws ConnectorException, NotFoundException, AlreadyExistException, AttributeException;

    ConnectorDetailDto editConnector(SecuredUUID uuid, ConnectorUpdateRequestDto request)
            throws NotFoundException, ConnectorException, AttributeException;

    void deleteConnector(SecuredUUID uuid) throws NotFoundException;

    List<ConnectInfo> connect(ConnectRequestDto request) throws ConnectorException;

    ConnectInfo reconnect(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    void approve(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkApprove(List<SecuredUUID> uuids);

    List<BulkActionMessageDto> bulkReconnect(List<SecuredUUID> uuids);

    List<BulkActionMessageDto> bulkDeleteConnector(List<SecuredUUID> uuids);

    List<BulkActionMessageDto> forceDeleteConnector(List<SecuredUUID> uuids);

    HealthInfo checkHealth(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    ConnectorInfo getInfo(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();
}
