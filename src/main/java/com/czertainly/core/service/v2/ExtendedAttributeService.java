package com.czertainly.core.service.v2;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.RaProfile;

import java.util.List;

public interface ExtendedAttributeService {
    List<BaseAttribute> listIssueCertificateAttributes(
            RaProfile raProfile) throws ConnectorException, NotFoundException;

    boolean validateIssueCertificateAttributes(
            RaProfile raProfile,
            List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException;

    List<BaseAttribute> listRevokeCertificateAttributes(
            RaProfile raProfile) throws ConnectorException, NotFoundException;

    boolean validateRevokeCertificateAttributes(
            RaProfile raProfile,
            List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException;

    void mergeAndValidateIssueAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException;

    void mergeAndValidateRevokeAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException;

    void validateLegacyConnector(Connector connector) throws NotFoundException;
}
