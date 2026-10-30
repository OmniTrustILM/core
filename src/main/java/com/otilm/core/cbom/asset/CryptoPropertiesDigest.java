package com.otilm.core.cbom.asset;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.otilm.core.cbom.asset.identity.AsciiText;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HexFormat;
import java.util.Map;

/**
 * The merge bookkeeping for one {@code cryptoProperties} payload: how much it says, and exactly what it says.
 *
 * <p>
 * {@code leafCount} is the richness measure the merge elects on -- the payload describing an asset in the most detail
 * wins -- and {@code hash} both breaks ties deterministically and detects that a source's payload changed without
 * comparing whole documents.
 *
 * <p>
 * The hash is taken over a key-ordered rendering, so two payloads that differ only in member order agree. Without that,
 * a re-parse of the same document could elect a different source on every sync.
 *
 * <p>
 * A {@code null} payload yields {@code (0, null)} -- the pairing the {@code ck_crypto_asset_properties_pair} check
 * constraint enforces at the column level.
 */
public record CryptoPropertiesDigest(int leafCount, String hash) {

    private static final CryptoPropertiesDigest ABSENT = new CryptoPropertiesDigest(0, null);

    private static final ObjectWriter KEY_ORDERED_WRITER = ObjectMapperFactory
            .jsonColumn()
            .writer()
            .with(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    public static CryptoPropertiesDigest of(Map<String, Object> properties) {
        if (properties == null) {
            return ABSENT;
        }
        return new CryptoPropertiesDigest(leafCount(properties), hash(properties));
    }

    /**
     * Scalars reachable in the payload. Containers are structure, not content: an object with three empty objects in it
     * says nothing more than an empty object does, and must not out-rank a source that actually reported a curve.
     */
    static int leafCount(Object node) {
        // An explicit JSON null is a declared absence, not content. Counting it would let {"primitive":null,
        // "mode":null} out-rank {"curve":"P-256"} in the merge election and hide a real value behind an empty one.
        if (node == null) {
            return 0;
        }
        if (node instanceof Map<?, ?> map) {
            return map.values().stream().mapToInt(CryptoPropertiesDigest::leafCount).sum();
        }
        if (node instanceof Collection<?> collection) {
            return collection.stream().mapToInt(CryptoPropertiesDigest::leafCount).sum();
        }
        // A blank string is a declared absence too, for the same reason an explicit null is: it describes nothing.
        // Counting it let a source saying {"curve":" "} out-rank one that said nothing at all, so whitespace won
        // the election outright and became the row's stored view. The ratified rule counts it as zero.
        //
        // Blankness is decided by the specification's whitespace set rather than String.isBlank, which consults
        // Character.isWhitespace and therefore does not consider a no-break space blank -- and a no-break space is
        // exactly what arrives in text pasted out of a document.
        if (node instanceof String text) {
            return AsciiText.isBlank(text) ? 0 : 1;
        }
        return 1;
    }

    static String hash(Object node) {
        try {
            return HexFormat
                    .of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(KEY_ORDERED_WRITER.writeValueAsBytes(node)));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JCA specification; its absence is a broken JRE, not a runtime condition.
            throw new IllegalStateException("SHA-256 is not available", e);
        } catch (JsonProcessingException e) {
            // The payload came from parsed JSON, so it is maps, lists and scalars; nothing here can fail to serialize.
            // The message deliberately carries no payload content.
            throw new IllegalStateException("Cryptographic properties could not be rendered for hashing");
        }
    }
}
