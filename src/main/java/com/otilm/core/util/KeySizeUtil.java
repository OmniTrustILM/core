package com.otilm.core.util;

import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.slhdsa.BCSLHDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.pqc.jcajce.provider.falcon.BCFalconPublicKey;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class KeySizeUtil {

    private KeySizeUtil() {
    }

    private static final Map<FalconParameterSpec, Integer> falconKeySizes = Map.of(
            FalconParameterSpec.falcon_512, 7176,
            FalconParameterSpec.falcon_1024, 14344
    );

    private static final Map<MLDSAParameterSpec, Integer> mldsaKeySizes = Map.of(
            MLDSAParameterSpec.ml_dsa_44, 10496,
            MLDSAParameterSpec.ml_dsa_44_with_sha512, 10496,
            MLDSAParameterSpec.ml_dsa_65, 15616,
            MLDSAParameterSpec.ml_dsa_65_with_sha512, 15616,
            MLDSAParameterSpec.ml_dsa_87, 20736,
            MLDSAParameterSpec.ml_dsa_87_with_sha512, 20736
    );

    private static final Map<SLHDSAParameterSpec, Integer> slhdsaKeySizes = Map.ofEntries(
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_128f, 256),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_128s, 256),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256, 256),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_128s_with_sha256, 256),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_128f, 256),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_128s, 256),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128, 256),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128, 256),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_192f, 384),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_192s, 384),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_192f_with_sha512, 384),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_192s_with_sha512, 384),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_192f, 384),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_192s, 384),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256, 384),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256, 384),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_256f, 512),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_256s, 512),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_256f_with_sha512, 512),
            Map.entry(SLHDSAParameterSpec.slh_dsa_sha2_256s_with_sha512, 512),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_256f, 512),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_256s, 512),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256, 512),
            Map.entry(SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256, 512)
    );

    /**
     * Method to get the key length from the public Key.
     * For the Post Quantum Algorithm the key size is taken from the static map
     *
     * @param publicKey Public Key of the certificate
     * @return Key Size of the public Key
     */
    public static int getKeyLength(final PublicKey publicKey) {
        int len = -1;

        if (publicKey instanceof final RSAPublicKey rsaPublicKey) {
            return rsaPublicKey.getModulus().bitLength();
        } else if (publicKey instanceof final JCEECPublicKey jceecPublicKey) {
            return getJCECPublicKeyLength(jceecPublicKey);
        } else if (publicKey instanceof final ECPublicKey ecPublicKey) {
            final java.security.spec.ECParameterSpec spec = ecPublicKey.getParams();
            if (spec != null) {
                return spec.getOrder().bitLength(); // does this really return something we expect?
            } else {
                // We support the key, but we don't know the key length
                return  0;
            }
        } else if (publicKey instanceof final DSAPublicKey dsaPublicKey) {
            if (dsaPublicKey.getParams() != null) {
                return dsaPublicKey.getParams().getP().bitLength();
            } else {
                return dsaPublicKey.getY().bitLength();
            }
        } else if (publicKey instanceof final BCFalconPublicKey falconPublicKey) {
            return falconKeySizes.get(falconPublicKey.getParameterSpec());
        } else if (publicKey instanceof final BCMLDSAPublicKey mldsaPublicKey) {
            return mldsaKeySizes.get(mldsaPublicKey.getParameterSpec());
        } else if (publicKey instanceof final BCSLHDSAPublicKey slhdsaPublicKey) {
            return slhdsaKeySizes.get(slhdsaPublicKey.getParameterSpec());
        }
        return len;
    }

    private static int getJCECPublicKeyLength(JCEECPublicKey publicKey) {
        int len;
        final org.bouncycastle.jce.spec.ECParameterSpec spec = publicKey.getParameters();
        if (spec != null) {
            len = spec.getN().bitLength();
        } else {
            // We support the key, but we don't know the key length
            len = 0;
        }
        return len;
    }
}