package com.otilm.core.signing.tsa;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.formatting.SignatureFormattingClient;
import com.otilm.core.signing.tsa.signer.Signer;
import com.otilm.core.signing.tsa.signer.SignerFactory;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;

/**
 * Builds an RFC 3161 timestamp token for a signing profile, using a statically configured signing key and certificate.
 *
 * <p>Token assembly is a two-round-trip exchange with the signature-formatting connector because the
 * core never holds the private key: the signature-formatting connector owns ASN.1 encoding while the core manages signing.
 * <ol>
 *     <li><b>Format DTBS</b> — the connector encodes the TSTInfo and returns the exact data-to-be-signed.</li>
 *     <li><b>Sign</b> — the core's {@link Signer} signs that DTBS with the managed key.</li>
 *     <li><b>Format response</b> — the connector embeds the signature and returns the encoded token.</li>
 * </ol>
 * The returned bytes are parsed back into a {@link TimeStampToken} so the engine can optionally
 * verify the signature before granting the response.
 */
@Component
public class StaticKeyManagedTimestampTokenGenerator implements ManagedTimestampTokenGenerator {

    private final SignerFactory signerFactory;

    private final SignatureFormattingClient formatting;

    public StaticKeyManagedTimestampTokenGenerator(SignerFactory signerFactory, SignatureFormattingClient formatting) {
        this.signerFactory = signerFactory;
        this.formatting = formatting;
    }

    @Override
    public TimeStampToken generate(TspRequest request, ResolvedManagedTimestampingProfile timestampingProfile, CertificateChain certificateChain, BigInteger serialNumber, Instant genTime) throws TspException {

        Signer signer = signerFactory.create(timestampingProfile.resolvedScheme());
        SignatureAlgorithm signatureAlgorithm = signer.getSignatureAlgorithm();

        byte[] dtbs = formatting.formatDtbs(request, timestampingProfile, serialNumber, genTime,
                certificateChain, signatureAlgorithm);

        byte[] signature = signer.sign(dtbs);

        byte[] tokenBytes = formatting.formatSigningResponse(request, timestampingProfile, serialNumber, genTime, certificateChain, dtbs, signature, signatureAlgorithm);

        try {
            return new TimeStampToken(new CMSSignedData(tokenBytes));
        } catch (TSPException | IOException | CMSException e) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE, "Failed to parse assembled timestamp token", e, "Internal error during token parsing");
        }
    }
}
