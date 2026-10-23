package com.otilm.core.cbom.pqc;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The IANA spellings of TLS named groups that the name grammar does not read as an algorithm, onto the spelling it
 * does: a bare curve is the ECDH key agreement over it, {@code ffdhe2048} the finite-field group, and the glued hybrid
 * names are their hyphenated halves. Signature schemes ({@code ecdsa_secp256r1_sha256}, {@code rsa_pss_rsae_sha256},
 * {@code ed25519}, {@code mldsa65}) already read as the algorithms they name and pass through unchanged.
 */
final class TlsNames {

    private static final List<Map.Entry<Pattern, String>> GROUP_SPELLINGS = List
            .of(Map.entry(Pattern.compile("(?i)^(secp\\d{3}[rk]\\d)$"), "ECDH-$1"),
                    Map.entry(Pattern.compile("(?i)^(brainpoolP\\d{3}r1)(?:tls13)?$"), "ECDH-$1"),
                    Map.entry(Pattern.compile("(?i)^ffdhe(\\d{4})$"), "DH-ffdhe$1"),
                    Map.entry(Pattern.compile("(?i)^(secp\\d{3}r1|x25519|x448)mlkem(\\d{3,4})$"), "ECDH-$1-ML-KEM-$2"),
                    Map
                            .entry(Pattern.compile("(?i)^(secp\\d{3}r1|x25519|x448)kyber(\\d{3})(?:draft\\d+)?$"),
                                    "ECDH-$1-Kyber$2"));

    private TlsNames() {
    }

    /** The algorithm name a TLS group is judged as; the group's own spelling when no IANA shape matches. */
    static String algorithmNameOfGroup(String group) {
        for (Map.Entry<Pattern, String> spelling : GROUP_SPELLINGS) {
            Matcher matcher = spelling.getKey().matcher(group);
            if (matcher.matches()) {
                return matcher.replaceFirst(spelling.getValue());
            }
        }
        return group;
    }
}
