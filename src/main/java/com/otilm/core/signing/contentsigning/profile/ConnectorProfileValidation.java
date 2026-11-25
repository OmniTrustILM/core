package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.connector.signatures.contentsigning.common.ValidateProfileRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ValidateProfileResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureFamilyDeclarationDto;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.signing.contentsigning.declaration.ContentSigningDeclarations;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Asks a content-signing profile's formatting connector to judge the profile's values as a whole, because only the
 * connector knows whether a value, such as a font, can serve the signature it builds.
 */
@Component
public class ConnectorProfileValidation {

    private final ConnectorApiFactory connectorApiFactory;
    private final ContentSigningDeclarations declarations;

    public ConnectorProfileValidation(ConnectorApiFactory connectorApiFactory,
            ContentSigningDeclarations declarations) {
        this.connectorApiFactory = connectorApiFactory;
        this.declarations = declarations;
    }

    /**
     * Returns the document transfer modes the connector allows for the profile's values. A problem the connector
     * reports refuses the profile with a {@code ValidationException} naming the attribute.
     *
     * @throws ConnectorException when the connector cannot be reached, or answers a mode its family does not declare
     */
    public Set<DocumentTransferMode> validate(ApiClientConnectorInfo connector,
            ContentSigningWorkflowRequestDto workflow) throws ConnectorException {
        ValidateProfileResponseDto judgement = connectorApiFactory
                .getContentSigningFormattingApiClient(connector)
                .validateProfile(connector, validateProfileRequest(workflow));
        requireDeclaredModes(connector, workflow.getFamily(), judgement.getTransferModes());
        if (!judgement.getErrors().isEmpty()) {
            throw new ValidationException(judgement
                    .getErrors()
                    .stream()
                    .map(error -> ValidationError
                            .create("Formatting connector refused attribute {}: {}", error.getAttributeName(),
                                    error.getReason()))
                    .toList());
        }
        return judgement.getTransferModes();
    }

    private static ValidateProfileRequestDto validateProfileRequest(ContentSigningWorkflowRequestDto workflow) {
        ValidateProfileRequestDto request = new ValidateProfileRequestDto();
        request.setFamily(workflow.getFamily());
        request.setFormattingAttributes(new ArrayList<>(workflow.getSignatureFormattingConnectorAttributes()));
        request
                .setAllowedRequestAttributes(
                        new HashSet<>(Objects.requireNonNullElse(workflow.getAllowedRequestAttributes(), Set.of())));
        return request;
    }

    /**
     * The client checks the answer's shape, and Core checks its modes against the family declaration stored at
     * registration, refusing an undeclared one as the client refuses a malformed answer.
     */
    private void requireDeclaredModes(ApiClientConnectorInfo connector, String family,
            Set<DocumentTransferMode> answered) throws ConnectorException {
        Set<DocumentTransferMode> declared = declarations
                .family(UUID.fromString(connector.getUuid()), family)
                .map(SignatureFamilyDeclarationDto::getTransferModes)
                .orElseThrow(() -> new ConnectorException(
                        "Formatting connector withdrew family %s while the profile was validated".formatted(family),
                        connector));
        List<String> undeclared = answered
                .stream()
                .filter(mode -> !declared.contains(mode))
                .map(DocumentTransferMode::getCode)
                .toList();
        if (!undeclared.isEmpty()) {
            throw new ConnectorException(
                    "Formatting connector allowed transfer modes %s that family %s does not declare"
                            .formatted(undeclared, family),
                    connector);
        }
    }
}
