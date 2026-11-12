package com.otilm.core.util.builders;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.ContentSigningDeclarationDto;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureFamilyDeclarationDto;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureLevelDeclarationDto;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds a family declaration the way a connector serving the family would send it, by default PAdES up to ARCHIVAL
 * with no algorithm list, which accepts every algorithm. An AdES family carries its ETSI label and baseline level
 * names, and PAdES accepts only the document itself where other families also accept its digest.
 */
public final class SignatureFamilyDeclarationDtoBuilder {

    private static final Map<SignatureFamily, String> ADES_LABELS = Map
            .of(SignatureFamily.PADES, "PAdES", SignatureFamily.XADES, "XAdES", SignatureFamily.CADES, "CAdES",
                    SignatureFamily.JADES, "JAdES");

    private static final Map<SignatureLevel, String> BASELINE_SUFFIXES = Map
            .of(SignatureLevel.SIGNED, "B", SignatureLevel.TIMESTAMPED, "T", SignatureLevel.LONG_TERM, "LT",
                    SignatureLevel.ARCHIVAL, "LTA");

    private SignatureFamily code = SignatureFamily.PADES;
    private SignatureLevel highestLevel = SignatureLevel.ARCHIVAL;
    private Set<DocumentTransferMode> transferModes;
    private Set<SignatureAlgorithm> signatureAlgorithms;
    private final Map<SignatureLevel, String> levelNames = new EnumMap<>(SignatureLevel.class);

    public static SignatureFamilyDeclarationDtoBuilder aFamilyDeclaration() {
        return new SignatureFamilyDeclarationDtoBuilder();
    }

    public static SignatureFamilyDeclarationDtoBuilder aFamilyDeclaration(SignatureFamily code) {
        return new SignatureFamilyDeclarationDtoBuilder().withCode(code);
    }

    public SignatureFamilyDeclarationDtoBuilder withCode(SignatureFamily code) {
        this.code = code;
        return this;
    }

    public SignatureFamilyDeclarationDtoBuilder withHighestLevel(SignatureLevel highestLevel) {
        this.highestLevel = highestLevel;
        return this;
    }

    public SignatureFamilyDeclarationDtoBuilder withTransferModes(Set<DocumentTransferMode> transferModes) {
        this.transferModes = transferModes;
        return this;
    }

    public SignatureFamilyDeclarationDtoBuilder withSignatureAlgorithms(Set<SignatureAlgorithm> signatureAlgorithms) {
        this.signatureAlgorithms = signatureAlgorithms;
        return this;
    }

    public SignatureFamilyDeclarationDtoBuilder withLevelName(SignatureLevel level, String name) {
        this.levelNames.put(level, name);
        return this;
    }

    public SignatureFamilyDeclarationDto build() {
        String label = ADES_LABELS.getOrDefault(code, code.code());
        List<SignatureLevelDeclarationDto> levels = Arrays
                .stream(SignatureLevel.values())
                .filter(level -> level.isWithin(highestLevel))
                .map(level -> new SignatureLevelDeclarationDto(level,
                        levelNames.getOrDefault(level, label + "-B-" + BASELINE_SUFFIXES.get(level))))
                .toList();
        return new SignatureFamilyDeclarationDto(code, label, label + " signatures", new ArrayList<>(levels),
                transferModes != null ? transferModes : defaultTransferModes(), signatureAlgorithms);
    }

    public ContentSigningDeclarationDto buildDeclaration() {
        return new ContentSigningDeclarationDto(new ArrayList<>(List.of(build())));
    }

    private Set<DocumentTransferMode> defaultTransferModes() {
        return SignatureFamily.PADES.equals(code)
                ? EnumSet.of(DocumentTransferMode.INLINE)
                : EnumSet.of(DocumentTransferMode.INLINE, DocumentTransferMode.DIGEST_ONLY);
    }
}
