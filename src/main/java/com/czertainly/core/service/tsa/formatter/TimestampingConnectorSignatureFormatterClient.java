package com.czertainly.core.service.tsa.formatter;

import com.czertainly.api.clients.signing.SignatureFormatterApiClient;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.czertainly.api.model.connector.signatures.formatter.ExtensionDto;
import com.czertainly.api.model.connector.signatures.formatter.TimestampingFormatDtbsRequestDto;
import com.czertainly.api.model.connector.signatures.formatter.TimestampingFormatResponseRequestDto;
import com.czertainly.api.model.core.connector.v2.ConnectorApiClientDtoV2;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.scheme.SigningSchemeModel;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.czertainly.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.czertainly.core.service.tsa.CertificateChain;
import com.czertainly.core.service.tsa.messages.TspRequest;
import com.czertainly.core.service.v2.ConnectorService;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Component
public class TimestampingConnectorSignatureFormatterClient implements SignatureFormatterClient {

    private SignatureFormatterApiClient apiClient;
    private ConnectorService connectorService;

    @Autowired
    public void setApiClient(SignatureFormatterApiClient apiClient) {
        this.apiClient = apiClient;
    }

    @Autowired
    public void setService(ConnectorService service) {
        this.connectorService = service;
    }

    @Override
    public byte[] formatDtbs(TspRequest request,
                             SigningProfileModel<ManagedTimestampingWorkflow<? extends TimeQualityConfigurationModel>, ? extends SigningSchemeModel> timestampingProfile,
                             BigInteger serialNumber,
                             Instant genTime,
                             CertificateChain certificateChain,
                             SignatureAlgorithm signatureAlgorithm) throws TspException {

        ManagedTimestampingWorkflow<? extends TimeQualityConfigurationModel> workflow = timestampingProfile.workflow();
        ConnectorApiClientDtoV2 connector = null;
        try {
            connector = connectorService.getConnectorForApiClient(workflow.signatureFormatterConnectorUuid());
        } catch (NotFoundException e) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE,
                    "Signature formatter connector not found: " + workflow.signatureFormatterConnectorUuid(), e,
                    "Internal error: signing configuration is invalid");
        }

        TimestampingFormatDtbsRequestDto requestDto = new TimestampingFormatDtbsRequestDto();
        requestDto.setData(request.hashedMessage());
        requestDto.setHashAlgorithm(request.hashAlgorithm());
        requestDto.setPolicy(request.policy().orElse(workflow.defaultPolicyId()));
        requestDto.setNonce(request.nonce().orElse(null));
        requestDto.setIncludeSignerCertificate(request.includeSignerCertificate());
        requestDto.setQualifiedTimestamp(timestampingProfile.workflow().isQualifiedTimestamp());
        requestDto.setRequestExtensions(toExtensionDtos(request.requestExtensions()));
        requestDto.setSerialNumber(serialNumber);
        requestDto.setSigningTime(genTime);
        requestDto.setAccuracy(workflow.timeQualityConfiguration().getAccuracy().orElse(null));
        requestDto.setSignatureAlgorithm(signatureAlgorithm);
        requestDto.setCertificateChain(encodeBase64DerChain(certificateChain));
        requestDto.setFormatAttributes(workflow.signatureFormatterConnectorAttributes());

        try {
            return apiClient.formatDtbs(connector, requestDto).getDtbs();
        } catch (ConnectorException e) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE, "Signature formatter connector communication failed during DTBS phase: " + e.getMessage(), e, "Internal error during DTBS formatting");
        }
    }

    @Override
    public byte[] formatSigningResponse(TspRequest request,
                                        SigningProfileModel<ManagedTimestampingWorkflow<? extends TimeQualityConfigurationModel>, ? extends SigningSchemeModel> timestampingProfile,
                                        BigInteger serialNumber,
                                        Instant genTime,
                                        CertificateChain certificateChain,
                                        byte[] dtbs,
                                        byte[] signature,
                                        SignatureAlgorithm signatureAlgorithm) throws TspException {

        ManagedTimestampingWorkflow<? extends TimeQualityConfigurationModel> workflow = timestampingProfile.workflow();
        ConnectorApiClientDtoV2 connector = null;
        try {
            connector = connectorService.getConnectorForApiClient(workflow.signatureFormatterConnectorUuid());
        } catch (NotFoundException e) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE,
                    "Signature formatter connector not found: " + workflow.signatureFormatterConnectorUuid(), null,
                    "Internal error: signing configuration is invalid");
        }

        TimestampingFormatResponseRequestDto requestDto = new TimestampingFormatResponseRequestDto();
        requestDto.setDtbs(dtbs);
        requestDto.setSignature(signature);
        requestDto.setCertificateChain(encodeBase64DerChain(certificateChain));
        requestDto.setFormatAttributes(workflow.signatureFormatterConnectorAttributes());
        requestDto.setData(request.hashedMessage());
        requestDto.setHashAlgorithm(request.hashAlgorithm());
        requestDto.setPolicy(request.policy().orElse(workflow.defaultPolicyId()));
        requestDto.setNonce(request.nonce().orElse(null));
        requestDto.setIncludeSignerCertificate(request.includeSignerCertificate());
        requestDto.setQualifiedTimestamp(timestampingProfile.workflow().isQualifiedTimestamp());
        requestDto.setRequestExtensions(toExtensionDtos(request.requestExtensions()));
        requestDto.setSerialNumber(serialNumber);
        requestDto.setSigningTime(genTime);
        requestDto.setAccuracy(workflow.timeQualityConfiguration().getAccuracy().orElse(null));
        requestDto.setSignatureAlgorithm(signatureAlgorithm);

        try {
            return apiClient.formatSigningResponse(connector, requestDto).getResponse();
        } catch (ConnectorException e) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE, "Signature formatter connector communication failed during response assembly: " + e.getMessage(), e, "Internal error assembling timestamp token");
        }
    }

    private static List<ExtensionDto> toExtensionDtos(Extensions extensions) throws TspException {
        if (extensions == null)
            return Collections.emptyList();
        try {
            return Arrays.stream(extensions.getExtensionOIDs()).map(oid -> {
                Extension ext = extensions.getExtension(oid);
                ExtensionDto dto = new ExtensionDto();
                dto.setOid(oid.getId());
                dto.setCritical(ext.isCritical());
                dto.setValue(Base64.getEncoder().encodeToString(ext.getExtnValue().getOctets()));
                return dto;
            }).toList();
        } catch (Exception e) {
            throw new TspException(TspFailureInfo.BAD_DATA_FORMAT, "Failed to encode request extensions: " + e.getMessage(), e, "Invalid request extensions");
        }
    }

    private static List<byte[]> encodeBase64DerChain(CertificateChain certificateChain) throws TspException {
        try {
            return certificateChain.chain().stream().map(cert -> {
                try {
                    return Base64.getEncoder().encode(cert.getEncoded());
                } catch (CertificateEncodingException e) {
                    throw new RuntimeException(e);
                }
            }).toList();
        } catch (Exception e) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE, "Failed to encode certificate chain: " + e.getMessage(), e, "Internal error encoding certificate chain");
        }
    }
}
