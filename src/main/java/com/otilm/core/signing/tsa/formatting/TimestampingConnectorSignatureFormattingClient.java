package com.otilm.core.signing.tsa.formatting;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.signatures.formatting.ExtensionDto;
import com.otilm.api.model.connector.signatures.formatting.TimestampingFormatDtbsRequestDto;
import com.otilm.api.model.connector.signatures.formatting.TimestampingFormatResponseRequestDto;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.signing.engine.CertificateChain;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.tsa.messages.TspRequest;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.springframework.stereotype.Component;

@Component
public class TimestampingConnectorSignatureFormattingClient implements SignatureFormattingClient {

    private final ConnectorApiFactory connectorApiFactory;

    public TimestampingConnectorSignatureFormattingClient(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Override
    public byte[] formatDtbs(TspRequest request, ResolvedManagedTimestampingProfile timestampingProfile,
            BigInteger serialNumber, Instant genTime, CertificateChain certificateChain,
            SignatureAlgorithm signatureAlgorithm) throws SigningEngineException {

        ApiClientConnectorInfo connector = timestampingProfile.signatureFormattingConnector();

        TimestampingFormatDtbsRequestDto requestDto = new TimestampingFormatDtbsRequestDto();
        requestDto.setData(request.hashedMessage());
        requestDto.setHashAlgorithm(request.hashAlgorithm());
        requestDto.setPolicy(request.policy().orElse(timestampingProfile.defaultPolicyId()));
        requestDto.setNonce(request.nonce().orElse(null));
        requestDto.setIncludeSignerCertificate(request.includeSignerCertificate());
        requestDto.setQualifiedTimestamp(timestampingProfile.isQualifiedTimestamp());
        requestDto.setRequestExtensions(toExtensionDtos(request.requestExtensions()));
        requestDto.setSerialNumber(serialNumber);
        requestDto.setSigningTime(genTime);
        requestDto.setAccuracy(timestampingProfile.timeQualityConfiguration().getAccuracy().orElse(null));
        requestDto.setSignatureAlgorithm(signatureAlgorithm);
        requestDto.setCertificateChain(encodeDerChain(certificateChain));
        requestDto.setFormatAttributes(timestampingProfile.signatureFormattingConnectorAttributes());

        try {
            return connectorApiFactory
                    .getSignatureFormattingApiClient(connector)
                    .formatDtbs(connector, requestDto)
                    .getDtbs();
        } catch (ConnectorException e) {
            throw SigningEngineException
                    .stepFailed(SigningEngineFailure.CONNECTOR_FAULT, "formatDtbs",
                            "Signature formatting connector communication failed during DTBS phase: " + e.getMessage(),
                            e, "Internal error during DTBS formatting");
        }
    }

    @Override
    public byte[] formatSigningResponse(TspRequest request, ResolvedManagedTimestampingProfile timestampingProfile,
            BigInteger serialNumber, Instant genTime, CertificateChain certificateChain, byte[] dtbs, byte[] signature,
            SignatureAlgorithm signatureAlgorithm) throws SigningEngineException {

        ApiClientConnectorInfo connector = timestampingProfile.signatureFormattingConnector();

        TimestampingFormatResponseRequestDto requestDto = new TimestampingFormatResponseRequestDto();
        requestDto.setDtbs(dtbs);
        requestDto.setSignature(signature);
        requestDto.setCertificateChain(encodeDerChain(certificateChain));
        requestDto.setFormatAttributes(timestampingProfile.signatureFormattingConnectorAttributes());
        requestDto.setData(request.hashedMessage());
        requestDto.setHashAlgorithm(request.hashAlgorithm());
        requestDto.setPolicy(request.policy().orElse(timestampingProfile.defaultPolicyId()));
        requestDto.setNonce(request.nonce().orElse(null));
        requestDto.setIncludeSignerCertificate(request.includeSignerCertificate());
        requestDto.setQualifiedTimestamp(timestampingProfile.isQualifiedTimestamp());
        requestDto.setRequestExtensions(toExtensionDtos(request.requestExtensions()));
        requestDto.setSerialNumber(serialNumber);
        requestDto.setSigningTime(genTime);
        requestDto.setAccuracy(timestampingProfile.timeQualityConfiguration().getAccuracy().orElse(null));
        requestDto.setSignatureAlgorithm(signatureAlgorithm);

        try {
            return connectorApiFactory
                    .getSignatureFormattingApiClient(connector)
                    .formatSigningResponse(connector, requestDto)
                    .getResponse();
        } catch (ConnectorException e) {
            throw SigningEngineException
                    .stepFailed(SigningEngineFailure.CONNECTOR_FAULT, "formatSigningResponse",
                            "Signature formatting connector communication failed during response assembly: "
                                    + e.getMessage(),
                            e, "Internal error assembling timestamp token");
        }
    }

    private static List<ExtensionDto> toExtensionDtos(Extensions extensions) throws SigningEngineException {
        if (extensions == null) {
            return Collections.emptyList();
        }
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
            throw new SigningEngineException(SigningEngineFailure.MALFORMED_INPUT,
                    "Failed to encode request extensions: " + e.getMessage(), e, "Invalid request extensions");
        }
    }

    private static List<byte[]> encodeDerChain(CertificateChain certificateChain) throws SigningEngineException {
        List<byte[]> result = new ArrayList<>();
        for (X509Certificate certificate : certificateChain.chain()) {
            try {
                result.add(certificate.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                        "Failed to encode certificate chain: " + e.getMessage(), e,
                        "Internal error encoding certificate chain");
            }
        }
        return result;
    }
}
