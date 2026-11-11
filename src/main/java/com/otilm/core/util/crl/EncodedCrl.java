package com.otilm.core.util.crl;

import com.otilm.api.exception.PlatformException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * A CRL read from its encoding without holding all its entries decoded at once.
 *
 * <p>
 * The JDK parser builds an object for every entry and keeps them all, about 400 bytes each, so a CRL listing hundreds
 * of thousands of certificates takes well over a hundred megabytes of heap while it is read. This keeps the encoding
 * and decodes the entries one at a time whenever they are iterated:
 * <ul>
 * <li>the JDK parses the header, everything but the entries, from a copy of the CRL without them, so it reads the
 * issuer, the dates and the extensions and refuses a CRL whose signed signature algorithm differs from the outer
 * one;</li>
 * <li>the signature is verified over the CRL's own signed part, as the JDK verifies it;</li>
 * <li>BouncyCastle decodes the entries, once while parsing, so a malformed entry refuses the whole CRL before anything
 * is stored, and again for each iteration.</li>
 * </ul>
 * A CRL that is not DER-encoded at the levels read here, such as one with an indefinite length, is parsed whole by the
 * JDK, up to {@value #MAX_WHOLE_PARSE_SIZE} bytes.
 *
 * <p>
 * Parsing happens before the signature is verified, so a CRL from an untrusted URL is read within limits: the header at
 * most {@value #MAX_WHOLE_PARSE_SIZE} bytes, each entry at most {@value #MAX_ENTRY_SIZE} bytes before BouncyCastle
 * decodes it, and the signed list at most the {@value #MAX_SIGNED_LIST_FIELDS} fields a CRL has.
 */
public final class EncodedCrl {

    static final int MAX_WHOLE_PARSE_SIZE = 1024 * 1024;
    static final int MAX_ENTRY_SIZE = 64 * 1024;
    static final int MAX_SIGNED_LIST_FIELDS = 7;

    private static final Logger logger = LoggerFactory.getLogger(EncodedCrl.class);

    private static final int TAG_SEQUENCE = 0x30;
    private static final int TAG_UTC_TIME = 0x17;
    private static final int TAG_GENERALIZED_TIME = 0x18;
    private static final byte[] PEM_BEGIN = "-----BEGIN ".getBytes(US_ASCII);
    private static final byte[] PEM_DASHES = "-----".getBytes(US_ASCII);

    private final byte[] encoding;
    private final X509CRL header;
    private final int signedStart;
    private final int signedEnd;
    private final int entriesStart;
    private final int entriesEnd;
    private final Date lastRevocationDate;
    private final boolean parsedWhole;

    private EncodedCrl(byte[] encoding, X509CRL header, Span signed, Span entries, Date lastRevocationDate,
            boolean parsedWhole) {
        this.encoding = encoding;
        this.header = header;
        this.signedStart = signed.start();
        this.signedEnd = signed.end();
        this.entriesStart = entries.start();
        this.entriesEnd = entries.end();
        this.lastRevocationDate = lastRevocationDate;
        this.parsedWhole = parsedWhole;
    }

    /**
     * Reads a DER- or PEM-encoded CRL. Bytes after the CRL are ignored, as the JDK ignores them.
     *
     * @throws CRLException when the CRL or one of its entries is malformed
     */
    public static EncodedCrl parse(byte[] input) throws CRLException {
        byte[] der = removePemArmour(input);
        try {
            return parseStreamed(der);
        } catch (NotDerException e) {
            if (der.length > MAX_WHOLE_PARSE_SIZE) {
                throw new CrlRefusedException("it is not DER-encoded and larger than 1 MB, the most read whole");
            }
            return parseWhole(der);
        }
    }

    /**
     * The CRL without its entries, for its issuer, dates and extensions. Do not verify its signature: it does not cover
     * this copy; use {@link #isSignedBy}.
     */
    public X509CRL header() {
        return header;
    }

    /** Whether the key verifies the CRL's signature, with the CRL's signature algorithm and parameters. */
    public boolean isSignedBy(PublicKey publicKey) {
        try {
            if (parsedWhole) {
                header.verify(publicKey);
                return true;
            }
            Signature verifier = Signature.getInstance(header.getSigAlgName());
            AlgorithmParameterSpec parameters = signatureParameters(header);
            if (parameters != null) {
                // set before the key, as the JDK does, so a key restricted to other parameters is refused
                verifier.setParameter(parameters);
            }
            verifier.initVerify(publicKey);
            verifier.update(encoding, signedStart, signedEnd - signedStart);
            return verifier.verify(header.getSignature());
        } catch (GeneralSecurityException | ProviderException e) {
            logger.debug("CRL signature does not verify with the key: {}", e.getMessage());
            return false;
        }
    }

    /** The entries, decoded anew for each iteration. */
    public Iterable<RevokedCertificate> entries() {
        if (parsedWhole) {
            return wholeEntries(header);
        }
        return () -> new EntryIterator(encoding, entriesStart, entriesEnd);
    }

    /** The latest revocation date of the entries, or {@code null} when the CRL lists none. */
    public Date lastRevocationDate() {
        return lastRevocationDate == null ? null : new Date(lastRevocationDate.getTime());
    }

    private static EncodedCrl parseStreamed(byte[] der) throws CRLException, NotDerException {
        Tlv crl = Tlv.read(der, 0, der.length);
        Tlv signed = crl.tag() == TAG_SEQUENCE ? Tlv.read(der, crl.contentStart(), crl.end()) : null;
        if (signed == null || signed.tag() != TAG_SEQUENCE) {
            throw new CRLException("The CRL is not a sequence of a signed list, an algorithm and a signature");
        }
        List<Tlv> fields = new ArrayList<>(MAX_SIGNED_LIST_FIELDS);
        int at = signed.contentStart();
        while (at < signed.end()) {
            if (fields.size() == MAX_SIGNED_LIST_FIELDS) {
                throw new CRLException("The CRL's signed list has more fields than a CRL has");
            }
            Tlv field = Tlv.read(der, at, signed.end());
            fields.add(field);
            at = field.end();
        }
        int entriesField = indexOfRevokedCertificates(fields);
        Span entries = entriesField < 0
                ? new Span(signed.end(), signed.end())
                : new Span(fields.get(entriesField).contentStart(), fields.get(entriesField).end());
        int entriesFieldSize = entriesField < 0 ? 0 : fields.get(entriesField).end() - fields.get(entriesField).start();
        if (crl.end() - crl.contentStart() - entriesFieldSize > MAX_WHOLE_PARSE_SIZE) {
            throw new CrlRefusedException("everything but its entries is larger than 1 MB");
        }
        X509CRL header = parseJdk(headerOnly(der, crl, signed, fields, entriesField));
        Date lastRevocationDate = checkEntries(der, entries);
        return new EncodedCrl(der, header, new Span(signed.start(), signed.end()), entries, lastRevocationDate, false);
    }

    private static EncodedCrl parseWhole(byte[] der) throws CRLException {
        X509CRL crl = parseJdk(der);
        Date lastRevocationDate = null;
        for (RevokedCertificate entry : wholeEntries(crl)) {
            lastRevocationDate = later(lastRevocationDate, entry.revocationDate());
        }
        return new EncodedCrl(der, crl, new Span(0, 0), new Span(0, 0), lastRevocationDate, true);
    }

    /** The revoked certificates follow thisUpdate and the optional nextUpdate, the only times in the list. */
    private static int indexOfRevokedCertificates(List<Tlv> fields) {
        int index = 0;
        while (index < fields.size() && !isTime(fields.get(index))) {
            index++;
        }
        index++;
        if (index < fields.size() && isTime(fields.get(index))) {
            index++;
        }
        return index < fields.size() && fields.get(index).tag() == TAG_SEQUENCE ? index : -1;
    }

    private static boolean isTime(Tlv field) {
        return field.tag() == TAG_UTC_TIME || field.tag() == TAG_GENERALIZED_TIME;
    }

    /** The CRL with every field but the entries, and everything after the signed list as it is. */
    private static byte[] headerOnly(byte[] der, Tlv crl, Tlv signed, List<Tlv> fields, int entriesField) {
        ByteArrayOutputStream signedContent = new ByteArrayOutputStream();
        for (int i = 0; i < fields.size(); i++) {
            if (i != entriesField) {
                signedContent.write(der, fields.get(i).start(), fields.get(i).end() - fields.get(i).start());
            }
        }
        ByteArrayOutputStream crlContent = new ByteArrayOutputStream();
        writeSequence(crlContent, signedContent.toByteArray());
        crlContent.write(der, signed.end(), crl.end() - signed.end());
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        writeSequence(header, crlContent.toByteArray());
        return header.toByteArray();
    }

    private static void writeSequence(ByteArrayOutputStream out, byte[] content) {
        out.write(TAG_SEQUENCE);
        int length = content.length;
        if (length < 0x80) {
            out.write(length);
        } else {
            int lengthBytes = (Integer.SIZE - Integer.numberOfLeadingZeros(length) + 7) / 8;
            out.write(0x80 | lengthBytes);
            for (int shift = (lengthBytes - 1) * 8; shift >= 0; shift -= 8) {
                out.write(length >>> shift);
            }
        }
        out.write(content, 0, content.length);
    }

    /**
     * Decodes every entry once, so a malformed one refuses the CRL, and returns their latest revocation date. Each
     * entry is measured first: BouncyCastle decodes all elements of a sequence before checking how many there may be.
     */
    private static Date checkEntries(byte[] der, Span entries) throws CRLException, NotDerException {
        int at = entries.start();
        while (at < entries.end()) {
            Tlv entry = Tlv.read(der, at, entries.end());
            if (entry.end() - entry.start() > MAX_ENTRY_SIZE) {
                throw new CrlRefusedException("one of its entries is larger than 64 KB");
            }
            at = entry.end();
        }
        Date lastRevocationDate = null;
        try {
            Iterator<RevokedCertificate> iterator = new EntryIterator(der, entries.start(), entries.end());
            while (iterator.hasNext()) {
                lastRevocationDate = later(lastRevocationDate, iterator.next().revocationDate());
            }
        } catch (RuntimeException e) {
            throw new CRLException("A revoked certificate entry of the CRL is malformed", e);
        }
        return lastRevocationDate;
    }

    private static Date later(Date current, Date candidate) {
        return current == null || candidate.after(current) ? candidate : current;
    }

    private static List<RevokedCertificate> wholeEntries(X509CRL crl) {
        Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
        if (entries == null) {
            return List.of();
        }
        List<RevokedCertificate> revokedCertificates = new ArrayList<>(entries.size());
        for (X509CRLEntry entry : entries) {
            revokedCertificates
                    .add(new RevokedCertificate(entry.getSerialNumber(), entry.getRevocationDate(),
                            entry.getRevocationReason()));
        }
        return revokedCertificates;
    }

    private static X509CRL parseJdk(byte[] der) throws CRLException {
        try {
            return (X509CRL) CertificateFactory.getInstance("X509").generateCRL(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new CRLException("No X.509 certificate factory is available", e);
        }
    }

    /**
     * The parameters of the signature algorithm, read as the JDK reads them to verify a CRL: those of RSASSA-PSS, or a
     * curve for ECDSA.
     */
    private static AlgorithmParameterSpec signatureParameters(X509CRL crl) throws GeneralSecurityException {
        byte[] encoded = crl.getSigAlgParams();
        if (encoded == null) {
            return null;
        }
        String algorithm = crl.getSigAlgName().toUpperCase(Locale.ROOT);
        try {
            if (algorithm.contains("RSA")) {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("RSASSA-PSS");
                parameters.init(encoded);
                return parameters.getParameterSpec(PSSParameterSpec.class);
            }
            if (algorithm.contains("ECDSA")) {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(encoded);
                return parameters.getParameterSpec(ECParameterSpec.class);
            }
        } catch (IOException e) {
            throw new InvalidAlgorithmParameterException("Malformed signature algorithm parameters", e);
        }
        throw new InvalidAlgorithmParameterException(
                "Unrecognized algorithm for signature parameters " + crl.getSigAlgName());
    }

    /**
     * Takes the DER encoding out of PEM armour, which the JDK reads too; DER input starts with a sequence tag. The
     * markers are found in the bytes and only the armoured range is decoded, so the input is not copied as text.
     */
    private static byte[] removePemArmour(byte[] input) throws CRLException {
        if (input.length > 0 && (input[0] & 0xff) == TAG_SEQUENCE) {
            return input;
        }
        int begin = indexOf(input, PEM_BEGIN, 0);
        int labelStart = begin + PEM_BEGIN.length;
        int labelEnd = begin < 0 ? -1 : indexOf(input, PEM_DASHES, labelStart);
        if (labelEnd < 0) {
            throw new CRLException("The CRL is neither DER- nor PEM-encoded");
        }
        String label = new String(input, labelStart, labelEnd - labelStart, US_ASCII);
        int contentStart = labelEnd + PEM_DASHES.length;
        int end = indexOf(input, ("-----END " + label + "-----").getBytes(US_ASCII), contentStart);
        if (end < 0) {
            throw new CRLException("The PEM-encoded CRL has no matching end line");
        }
        byte[] decoded = new byte[(end - contentStart) / 4 * 3 + 3];
        try (InputStream base64 = Base64
                .getMimeDecoder()
                .wrap(new ByteArrayInputStream(input, contentStart, end - contentStart))) {
            int length = base64.readNBytes(decoded, 0, decoded.length);
            return Arrays.copyOf(decoded, length);
        } catch (IOException | IllegalArgumentException e) {
            throw new CRLException("The PEM-encoded CRL is not valid Base64", e);
        }
    }

    private static int indexOf(byte[] data, byte[] marker, int from) {
        for (int i = Math.max(from, 0); i <= data.length - marker.length; i++) {
            if (Arrays.equals(data, i, i + marker.length, marker, 0, marker.length)) {
                return i;
            }
        }
        return -1;
    }

    private record Span(int start, int end) {
    }

    /** A tag, length and value read from DER: one-byte tags and minimal definite lengths only. */
    private record Tlv(int tag, int start, int contentStart, int end) {

        static Tlv read(byte[] der, int at, int limit) throws CRLException, NotDerException {
            if (limit - at < 2) {
                throw new CRLException("The CRL is truncated");
            }
            int tag = der[at] & 0xff;
            if ((tag & 0x1f) == 0x1f) {
                throw new NotDerException();
            }
            int firstLengthByte = der[at + 1] & 0xff;
            int contentStart = at + 2;
            long length;
            if (firstLengthByte < 0x80) {
                length = firstLengthByte;
            } else if (firstLengthByte == 0x80) {
                throw new NotDerException();
            } else {
                int lengthBytes = firstLengthByte & 0x7f;
                if (lengthBytes > 4 || limit - contentStart < lengthBytes) {
                    throw new CRLException("The CRL is truncated or declares an impossible length");
                }
                if (der[contentStart] == 0) {
                    throw new NotDerException();
                }
                length = 0;
                for (int i = 0; i < lengthBytes; i++) {
                    length = (length << 8) | (der[contentStart++] & 0xff);
                }
                if (length < 0x80) {
                    throw new NotDerException();
                }
            }
            if (length > limit - contentStart) {
                throw new CRLException("The CRL is truncated");
            }
            return new Tlv(tag, at, contentStart, contentStart + (int) length);
        }
    }

    /** An encoding the DER reading here does not take; the JDK may still read it whole. */
    private static final class NotDerException extends Exception implements PlatformException {
        NotDerException() {
            super(null, null, false, false);
        }
    }

    private static final class EntryIterator implements Iterator<RevokedCertificate> {

        private final ASN1InputStream entries;
        private ASN1Primitive next;

        EntryIterator(byte[] der, int start, int end) {
            this.entries = new ASN1InputStream(new ByteArrayInputStream(der, start, end - start), end - start);
            this.next = readNext();
        }

        @Override
        public boolean hasNext() {
            return next != null;
        }

        @Override
        public RevokedCertificate next() {
            if (next == null) {
                throw new NoSuchElementException();
            }
            RevokedCertificate entry = decodeEntry(next);
            next = readNext();
            return entry;
        }

        private ASN1Primitive readNext() {
            try {
                return entries.readObject();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        /** Reads the reason code as the JDK does: a code it does not know reads as unspecified. */
        private static CRLReason jdkReason(BigInteger code) {
            CRLReason[] reasons = CRLReason.values();
            if (code.signum() > 0 && code.compareTo(BigInteger.valueOf(reasons.length)) < 0) {
                return reasons[code.intValue()];
            }
            return CRLReason.UNSPECIFIED;
        }

        private static RevokedCertificate decodeEntry(ASN1Primitive encoded) {
            TBSCertList.CRLEntry entry = TBSCertList.CRLEntry.getInstance(encoded);
            BigInteger serialNumber = entry.getUserCertificate().getValue();
            Date revocationDate = entry.getRevocationDate().getDate();
            CRLReason reason = null;
            Extensions extensions = entry.getExtensions();
            Extension reasonCode = extensions == null ? null : extensions.getExtension(Extension.reasonCode);
            if (reasonCode != null) {
                reason = jdkReason(ASN1Enumerated.getInstance(reasonCode.getParsedValue()).getValue());
            }
            return new RevokedCertificate(serialNumber, revocationDate, reason);
        }
    }
}
