package com.otilm.core.service.v2;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;

import java.util.List;

public interface ExtendedAttributeService {
    List<BaseAttribute> listIssueCertificateAttributes(
            RaProfile raProfile) throws ConnectorException, NotFoundException;

    void validateIssueCertificateAttributes(
            RaProfile raProfile,
            List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException;

    List<BaseAttribute> listRevokeCertificateAttributes(
            RaProfile raProfile) throws ConnectorException, NotFoundException;

    List<BaseAttribute> listRegisterCertificateAttributes(
            RaProfile raProfile) throws ConnectorException, NotFoundException;

    void validateRevokeCertificateAttributes(
            RaProfile raProfile,
            List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException;

    void mergeAndValidateIssueAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException;

    void mergeAndValidateRevokeAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException;

    void mergeAndValidateRegisterAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException;

    void validateLegacyConnector(Connector connector) throws NotFoundException;
}
