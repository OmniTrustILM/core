package com.otilm.core.util;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.ExtendedKeyUsageMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.KeyUsageMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.MappedField;
import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.oid.OidHandler;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

/**
 * Pure-kernel codec for the certificate extensions whose value is a flat set of scalars. The only place that knows
 * their ASN.1 shapes: encoding for the renderer and decoding for the parser live together so they cannot drift.
 *
 * <p>
 * Both directions speak the extension's <em>inner value</em> DER, base64-encoded — what
 * {@code getExtnValue().getOctets()} yields and what {@code ExtensionsGenerator.addExtension} consumes.
 *
 * <p>
 * Lives beside {@link X509RequestContentRenderer}, which is its only encoding caller, so that
 * {@code com.otilm.core.util} gains no dependency on {@code com.otilm.core.certificate.request} — that package already
 * depends on this one, and the reverse edge would close a cycle.
 *
 * <p>
 * No Spring context required; all methods are static.
 */
public final class StructuredExtensionCodec {

    public static final String KEY_USAGE_OID = SystemOid.KEY_USAGE.getOid();
    public static final String EXTENDED_KEY_USAGE_OID = SystemOid.EXTENDED_KEY_USAGE_EXTENSION.getOid();

    /** Operator-facing names, keyed by the target's extension OID. */
    private static final Map<String, String> TARGET_NAMES = Map
            .of(KEY_USAGE_OID, "Key Usage", EXTENDED_KEY_USAGE_OID, "Extended Key Usage");

    private StructuredExtensionCodec() {
    }

    /**
     * Decoded items, plus the ones the platform cannot name. An unrepresentable item must never be silently dropped:
     * the uploaded CSR is forwarded to the CA verbatim, so anything invisible to validation bypasses it.
     */
    public record Decoded<T>(List<T> values, List<String> unrepresentable) {
    }

    /**
     * The extension OID a structured mapping target addresses, or {@code null} when {@code field} is an RDN, SAN or
     * opaque extension target. Every caller branches on this rather than repeating the type patterns.
     */
    public static String oidFor(MappedField field) {
        return switch (field) {
            case KeyUsageMappedField ignored -> KEY_USAGE_OID;
            case ExtendedKeyUsageMappedField ignored -> EXTENDED_KEY_USAGE_OID;
            case null, default -> null;
        };
    }

    /** Operator-facing name of the structured target at {@code extensionOid}, or {@code null} if there is none. */
    public static String structuredTargetName(String extensionOid) {
        return TARGET_NAMES.get(extensionOid);
    }

    /** The definition's predefined content as plain strings — the items a structured target permits. */
    public static List<String> permittedItems(DataAttributeV3 definition) {
        List<BaseAttributeContentV3<?>> content = definition.getContent();
        if (content == null) {
            return List.of();
        }
        List<String> items = new ArrayList<>();
        for (BaseAttributeContentV3<?> item : content) {
            if (item.getData() instanceof String value) {
                items.add(value);
            }
        }
        return items;
    }

    public static List<CertificateKeyUsage> toKeyUsages(List<String> codes) {
        List<CertificateKeyUsage> usages = new ArrayList<>(codes.size());
        for (String code : codes) {
            try {
                usages.add(CertificateKeyUsage.fromCode(code));
            } catch (IllegalArgumentException e) {
                throw new ValidationException("'%s' is not a key usage".formatted(code));
            }
        }
        return usages;
    }

    /**
     * The dotted-decimal check is not sufficient on its own: it accepts arcs the ASN.1 encoding forbids, such as
     * {@code 1.40}, where a first arc of 0 or 1 caps the second at 39. Those would pass request validation and then
     * fail inside the encoder, so the parser that will do the encoding is the one that decides here.
     */
    public static List<String> toPurposeOids(List<String> oids) {
        for (String oid : oids) {
            if (!OidHandler.isOid(oid)) {
                throw new ValidationException(
                        "'%s' is not a dotted-decimal extended-key-usage purpose OID".formatted(oid));
            }
        }
        return List.copyOf(oids);
    }

    /**
     * Sets each usage at its X.509 bit position and trims trailing zero bits per DER minimal encoding.
     *
     * <p>
     * The position comes from {@link CertificateKeyUsage#getIndex()}. Neither {@code getBit()} (the database bitmask
     * layout) nor BouncyCastle's {@code KeyUsage} constants (a first-octet-major packed int) describe this encoding, so
     * no integer conversion happens here.
     *
     * @return {@code null} for an empty list — RFC 5280 forbids an empty key usage bit string
     */
    public static String encodeKeyUsage(List<CertificateKeyUsage> usages) {
        if (usages.isEmpty()) {
            return null;
        }
        byte[] bits = new byte[2];
        int highest = -1;
        for (CertificateKeyUsage usage : usages) {
            int index = usage.getIndex();
            bits[index / 8] |= (byte) (0x80 >>> index % 8);
            highest = Math.max(highest, index);
        }
        int padBits = 7 - highest % 8;
        return encoded(new DERBitString(Arrays.copyOf(bits, highest / 8 + 1), padBits));
    }

    /** @return {@code null} for an empty list — RFC 5280 forbids an empty extended key usage sequence */
    public static String encodeExtendedKeyUsage(List<String> purposeOids) {
        if (purposeOids.isEmpty()) {
            return null;
        }
        ASN1EncodableVector purposes = new ASN1EncodableVector();
        for (String purposeOid : purposeOids) {
            purposes.add(new ASN1ObjectIdentifier(purposeOid));
        }
        return encoded(new DERSequence(purposes));
    }

    public static Decoded<CertificateKeyUsage> decodeKeyUsage(String base64Value) {
        ASN1BitString bits = ASN1BitString.getInstance(parse(base64Value, KEY_USAGE_OID));
        byte[] bytes = bits.getBytes();
        int significantBits = bytes.length * 8 - bits.getPadBits();
        List<CertificateKeyUsage> usages = new ArrayList<>();
        List<String> unrepresentable = new ArrayList<>();
        for (int index = 0; index < significantBits; index++) {
            if (((bytes[index / 8] & 0xff) & 0x80 >>> index % 8) == 0) {
                continue;
            }
            try {
                usages.add(CertificateKeyUsage.fromIndex(index));
            } catch (IllegalArgumentException e) {
                unrepresentable.add("bit " + index);
            }
        }
        if (usages.isEmpty() && unrepresentable.isEmpty()) {
            // RFC 5280 4.2.1.3: when the extension appears, at least one bit MUST be set. A nominally non-empty
            // but all-zero string (03 02 07 00) has to fail here too: returning empty lists would make a present
            // extension indistinguishable from an absent one, so strict whitelisting could not see it.
            throw new IllegalArgumentException(
                    "Extension %s carries a key usage with no bits set".formatted(KEY_USAGE_OID));
        }
        return new Decoded<>(usages, unrepresentable);
    }

    public static List<String> decodeExtendedKeyUsage(String base64Value) {
        List<String> purposeOids = new ArrayList<>();
        for (ASN1Encodable purpose : ASN1Sequence.getInstance(parse(base64Value, EXTENDED_KEY_USAGE_OID))) {
            purposeOids.add(ASN1ObjectIdentifier.getInstance(purpose).getId());
        }
        if (purposeOids.isEmpty()) {
            // RFC 5280 4.2.1.12: the sequence holds one or more purposes. An empty one would be
            // indistinguishable from an absent extension, so validation could not see it.
            throw new IllegalArgumentException(
                    "Extension %s carries no extended key usage purposes".formatted(EXTENDED_KEY_USAGE_OID));
        }
        return purposeOids;
    }

    private static String encoded(ASN1Encodable value) {
        try {
            return Base64.getEncoder().encodeToString(value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        } catch (IOException e) {
            throw new ValidationException("Could not encode a structured certificate extension value");
        }
    }

    private static ASN1Primitive parse(String base64Value, String extensionOid) {
        try {
            return ASN1Primitive.fromByteArray(Base64.getDecoder().decode(base64Value));
        } catch (IOException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Extension %s does not carry parseable DER".formatted(extensionOid));
        }
    }
}
