package com.otilm.core.architecture;

import com.otilm.core.util.CryptographyUtil;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaCall;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaConstructor;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Keeps public-key decoding inside {@link CryptographyUtil}, because a decode that picks its own provider returns a JDK
 * key class wherever the JDK implements the algorithm, and Core inspects BouncyCastle key classes.
 */
@AnalyzeClasses(packages = "com.otilm.core", importOptions = ImportOption.DoNotIncludeTests.class)
class PublicKeyDecodingCentralizationArchTest {

    private static final String BOUNCY_CASTLE_PACKAGE = "org.bouncycastle.";

    private static final DescribedPredicate<JavaCall<?>> DECODES_A_PUBLIC_KEY = new DescribedPredicate<>(
            "decode a public key from its encoding") {

        @Override
        public boolean test(JavaCall<?> call) {
            JavaClass owner = call.getTargetOwner();
            if (JavaConstructor.CONSTRUCTOR_NAME.equals(call.getName())) {
                return owner.isEquivalentTo(X509EncodedKeySpec.class) || owner.isAssignableTo(PublicKey.class)
                        && owner.getPackageName().startsWith(BOUNCY_CASTLE_PACKAGE);
            }
            return "getPublicKey".equals(call.getName()) && (owner.isAssignableTo(BouncyCastleProvider.class)
                    || owner.isAssignableTo(JcaPEMKeyConverter.class)
                    || owner.isAssignableTo(JcaPKCS10CertificationRequest.class)
                    || owner.isAssignableTo(JcaCertificateRequestMessage.class));
        }
    };

    @ArchTest
    static final ArchRule onlyCryptographyUtilDecodesPublicKeys = noClasses()
            .that()
            .doNotBelongToAnyOf(CryptographyUtil.class)
            .should()
            .callCodeUnitWhere(DECODES_A_PUBLIC_KEY)
            .because("CryptographyUtil.decodePublicKey decodes a key as BouncyCastle decodes a certificate's, "
                    + "so a key is the same class on every JDK and in every caller");
}
