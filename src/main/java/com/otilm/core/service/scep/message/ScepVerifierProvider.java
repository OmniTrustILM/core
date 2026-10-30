package com.otilm.core.service.scep.message;

import java.security.PublicKey;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class ScepVerifierProvider implements SignerInformationVerifierProvider {

    private final SignerInformationVerifier signerInformationVerifier;

    public ScepVerifierProvider(PublicKey publicKey) throws OperatorCreationException {
        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME);
        JcaSignerInfoVerifierBuilder signerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(
                calculatorProviderBuilder.build()).setProvider(BouncyCastleProvider.PROVIDER_NAME);
        signerInformationVerifier = signerInfoVerifierBuilder.build(publicKey);
    }

    @Override
    public SignerInformationVerifier get(SignerId signerId) throws OperatorCreationException {
        return signerInformationVerifier;
    }
}
