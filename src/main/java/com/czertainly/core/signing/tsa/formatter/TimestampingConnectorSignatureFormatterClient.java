package com.czertainly.core.signing.tsa.formatter;

import com.czertainly.api.clients.signing.SignatureFormatterApiClient;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.czertainly.api.model.connector.signatures.formatter.ExtensionDto;
import com.czertainly.api.model.connector.signatures.formatter.TimestampingFormatDtbsRequestDto;
import com.czertainly.api.model.connector.signatures.formatter.TimestampingFormatResponseRequestDto;
import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.czertainly.core.signing.tsa.CertificateChain;
import com.czertainly.core.signing.tsa.messages.TspRequest;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Component
public class TimestampingConnectorSignatureFormatterClient implements SignatureFormatterClient {

    private SignatureFormatterApiClient apiClient;

    @Autowired
    public void setApiClient(SignatureFormatterApiClient apiClient) {
        this.apiClient = apiClient;
    }

    @Override
    public byte[] formatDtbs(TspRequest request,
                             ResolvedManagedTimestampingProfile timestampingProfile,
                             BigInteger serialNumber,
                             Instant genTime,
                             CertificateChain certificateChain,
                             SignatureAlgorithm signatureAlgorithm) throws TspException {

        ApiClientConnectorInfo connector = timestampingProfile.signatureFormatterConnector();

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
        requestDto.setFormatAttributes(timestampingProfile.signatureFormatterConnectorAttributes());

        try {
            return apiClient.formatDtbs(connector, requestDto).getDtbs();
        } catch (ConnectorException e) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE, "Signature formatter connector communication failed during DTBS phase: " + e.getMessage(), e, "Internal error during DTBS formatting");
        }
    }

    @Override
    public byte[] formatSigningResponse(TspRequest request,
                                        ResolvedManagedTimestampingProfile timestampingProfile,
                                        BigInteger serialNumber,
                                        Instant genTime,
                                        CertificateChain certificateChain,
                                        byte[] dtbs,
                                        byte[] signature,
                                        SignatureAlgorithm signatureAlgorithm) throws TspException {

        ApiClientConnectorInfo connector = timestampingProfile.signatureFormatterConnector();

        TimestampingFormatResponseRequestDto requestDto = new TimestampingFormatResponseRequestDto();
        requestDto.setDtbs(dtbs);
        requestDto.setSignature(signature);
        requestDto.setCertificateChain(encodeDerChain(certificateChain));
        requestDto.setFormatAttributes(timestampingProfile.signatureFormatterConnectorAttributes());
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

    private static List<byte[]> encodeDerChain(CertificateChain certificateChain) throws TspException {
        List<byte[]> result = new ArrayList<>();
        for (X509Certificate certificate : certificateChain.chain()) {
            try {
                result.add(certificate.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new TspException(TspFailureInfo.SYSTEM_FAILURE, "Failed to encode certificate chain: " + e.getMessage(), e, "Internal error encoding certificate chain");
            }
        }
        return result;
    }
}
