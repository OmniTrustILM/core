package com.otilm.core.api.tsp.parser;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.core.signing.tsa.messages.TspRequest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.tsp.TimeStampRequest;
import org.springframework.lang.NonNull;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

public class TspRequestParser {

    private TspRequestParser() {
        // Static utility class; prevent instantiation
    }

    public static TspRequest parse(byte[] body) throws TspRequestParsingException {
        TimeStampRequest tsr = getTimeStampRequest(body);

        var algorithmOid = tsr.getMessageImprintAlgOID().getId();
        DigestAlgorithm digestAlgorithm;
        try {
            digestAlgorithm = DigestAlgorithm.findByOid(algorithmOid);
        } catch (ValidationException e) {
            throw new TspRequestParsingException(TspFailureInfo.BAD_ALG,
                    "Unknown hash algorithm OID: " + algorithmOid, "Unknown hash algorithm");
        }

        var hashedMessage = tsr.getMessageImprintDigest();
        if (hashedMessage.length != digestAlgorithm.getDigestSizeBytes()) {
            throw new TspRequestParsingException(TspFailureInfo.BAD_DATA_FORMAT,
                    "Hash length %d does not match expected %d for %s".formatted(hashedMessage.length, digestAlgorithm.getDigestSizeBytes(), digestAlgorithm.getCode()),
                    "Invalid hash length");
        }

        Optional<String> policy = resolvePolicy(tsr);

        Optional<BigInteger> nonce = tsr.getNonce() != null ? Optional.of(tsr.getNonce()) : Optional.empty();
        boolean certReq = tsr.getCertReq();

        Extensions requestExtensions = getExtensions(tsr);

        return new TspRequest(digestAlgorithm, hashedMessage, policy, nonce, certReq, requestExtensions);
    }

    private static Extensions getExtensions(TimeStampRequest tsr) throws TspRequestParsingException {

        if (tsr.hasExtensions()) {
            @SuppressWarnings("unchecked")
            List<ASN1ObjectIdentifier> extensionOids = tsr.getExtensionOIDs();
            var extensions = new Extension[extensionOids.size()];
            for (int i = 0; i < extensionOids.size(); i++) {
                Extension extension = tsr.getExtension(extensionOids.get(i));
                ensureValidExtension(extension);
                extensions[i] = extension;
            }

            try {
                return new Extensions(extensions);
            } catch (IllegalArgumentException e) {
                throw new TspRequestParsingException(TspFailureInfo.BAD_DATA_FORMAT,
                        "Malformed request extensions: " + e.getMessage(), "Malformed request extensions");
            }
        } else {
            return null;
        }
    }

    /**
     * BouncyCastle leaves an extension's {@code extnValue} as an opaque OCTET STRING — it never decodes the
     * bytes inside. Confirm that inner content is at least well-formed DER; per-OID type checking is out of
     * scope because for now we accept all extensions.
     */
    private static void ensureValidExtension(Extension extension) throws TspRequestParsingException {
        try {
            ASN1Primitive.fromByteArray(extension.getExtnValue().getOctets());
        } catch (IOException e) {
            throw new TspRequestParsingException(TspFailureInfo.BAD_DATA_FORMAT,
                    "Extension %s has a malformed value: %s".formatted(extension.getExtnId().getId(), e.getMessage()),
                    "Malformed request extensions");
        }
    }

    @NonNull
    private static TimeStampRequest getTimeStampRequest(byte[] body) throws TspRequestParsingException {
        TimeStampRequest bcRequest;
        try {
            bcRequest = new TimeStampRequest(body);
        } catch (IOException | RuntimeException e) {
            // BC's TimeStampReq indexes the parsed SEQUENCE without bounds checks, so a truncated or empty
            // SEQUENCE surfaces as ArrayIndexOutOfBoundsException/NullPointerException rather than IOException.
            // All of these mean the same thing: the client sent a malformed request, not a server fault.
            throw new TspRequestParsingException(TspFailureInfo.BAD_REQUEST, "Malformed request: " + e.getMessage(),
                    "Malformed request");
        }
        return bcRequest;
    }

    private static Optional<String> resolvePolicy(TimeStampRequest bcRequest) {
        var reqPolicyOid = bcRequest.getReqPolicy();
        return reqPolicyOid != null ? Optional.of(reqPolicyOid.getId()) : Optional.empty();
    }
}
