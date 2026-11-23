package com.otilm.ai.proxy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** A fresh bounded CSI snapshot. No identity survives as a fallback for a later operation. */
public final class IdentityFiles {
    private static final int MAX_FILE_BYTES = 65536;
    private static final byte[] PAIR_CHECK = {73, 76, 77, 45, 112, 97, 105, 114};

    private IdentityFiles() {
    }

    static SSLContext load(ProxyConfiguration configuration) throws IOException, GeneralSecurityException {
        return load(configuration.certificateFile(), configuration.privateKeyFile(), configuration.serverCaFile());
    }

    /**
     * Trusted bootstrap paths only; construction supplies no native identity or operation authority. Callers must
     * enforce HTTPS hostname identification, a fixed destination and their operation budget.
     */
    public static SSLContext load(Path certificateFile, Path privateKeyFile, Path serverCaFile)
            throws IOException, GeneralSecurityException {
        try {
            return loadSnapshot(certificateFile, privateKeyFile, serverCaFile, false).context();
        } catch (IOException | GeneralSecurityException | RuntimeException unavailable) {
            throw invalid();
        }
    }

    /**
     * Fixed Core server snapshot for trusted bootstrap; the standard key-manager API exposes private key material.
     * Reload explicitly for new CSI material. Trusted paths supply no native identity or operation authority.
     */
    public static javax.net.ssl.X509ExtendedKeyManager loadServerKeys(Path certificateFile, Path privateKeyFile,
            Path serverCaFile) throws IOException, GeneralSecurityException {
        try {
            var material = loadSnapshot(certificateFile, privateKeyFile, serverCaFile, true);
            for (var manager : material.keyManagers()) {
                if (manager instanceof javax.net.ssl.X509ExtendedKeyManager serverKeys) {
                    return serverKeys;
                }
            }
            throw invalid();
        } catch (IOException | GeneralSecurityException | RuntimeException unavailable) {
            throw invalid();
        }
    }

    private record Loaded(SSLContext context, javax.net.ssl.KeyManager[] keyManagers) {
    }

    private static Loaded loadSnapshot(Path certificateFile, Path privateKeyFile, Path serverCaFile, boolean server)
            throws IOException, GeneralSecurityException {
        if (certificateFile == null || privateKeyFile == null || serverCaFile == null || !certificateFile.isAbsolute()
                || !privateKeyFile.isAbsolute() || !serverCaFile.isAbsolute()
                || certificateFile.normalize().getParent() == null || privateKeyFile.normalize().getParent() == null
                || serverCaFile.normalize().getParent() == null
                || !certificateFile.normalize().getParent().equals(privateKeyFile.normalize().getParent())) {
            throw invalid();
        }
        Path certificate = certificateFile.toRealPath();
        Path key = privateKeyFile.toRealPath();
        Path ca = serverCaFile.toRealPath();
        if (!certificate.getParent().equals(key.getParent())) {
            throw invalid();
        }
        BasicFileAttributes certificateState = attributes(certificate);
        BasicFileAttributes keyState = attributes(key);
        BasicFileAttributes caState = attributes(ca);
        byte[] certificateBytes = read(certificate);
        byte[] caBytes = read(ca);
        byte[] keyBytes = read(key);
        try {
            List<X509Certificate> chain = certificates(certificateBytes);
            List<X509Certificate> anchors = certificates(caBytes);
            List<byte[]> encodedKeys = pem(keyBytes, "PRIVATE KEY");
            if (encodedKeys.size() != 1) {
                throw invalid();
            }
            byte[] encoded = encodedKeys.getFirst();
            java.security.PrivateKey privateKey;
            try {
                privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(encoded));
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
            requireP256(privateKey);
            requireP256(chain.getFirst().getPublicKey());
            requireLeafUsage(chain.getFirst(), server);
            requireKeyPairAndChain(privateKey, chain);
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(null, null);
            keys.setKeyEntry("identity", privateKey, new char[0], chain.toArray(X509Certificate[]::new));
            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keys, new char[0]);
            KeyStore trust = trustedAnchors(anchors);
            if (server) {
                requireServerPath(chain, anchors);
            }
            TrustManagerFactory trustManagers = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
            unchanged(certificateFile, certificate, certificateState);
            unchanged(privateKeyFile, key, keyState);
            unchanged(serverCaFile, ca, caState);
            return new Loaded(context, keyManagers.getKeyManagers());
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    private static void requireLeafUsage(X509Certificate leaf, boolean server) throws GeneralSecurityException {
        boolean[] usage = leaf.getKeyUsage();
        List<String> extendedUsage = leaf.getExtendedKeyUsage();
        if ((usage != null && !usage[0])
                || (!server && extendedUsage != null && !extendedUsage.contains("1.3.6.1.5.5.7.3.2"))
                || server && (leaf.getBasicConstraints() >= 0 || usage == null || extendedUsage == null
                        || extendedUsage.size() != 1 || !extendedUsage.contains("1.3.6.1.5.5.7.3.1"))) {
            throw invalid();
        }
    }

    private static void requireKeyPairAndChain(java.security.PrivateKey privateKey, List<X509Certificate> chain)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(PAIR_CHECK);
        byte[] signed = signature.sign();
        signature.initVerify(chain.getFirst().getPublicKey());
        signature.update(PAIR_CHECK);
        if (!signature.verify(signed)) {
            throw invalid();
        }
        for (int i = 1; i < chain.size(); i++) {
            chain.get(i - 1).verify(chain.get(i).getPublicKey());
        }
    }

    private static KeyStore trustedAnchors(List<X509Certificate> anchors) throws IOException, GeneralSecurityException {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        for (int i = 0; i < anchors.size(); i++) {
            X509Certificate anchor = anchors.get(i);
            boolean[] keyUsage = anchor.getKeyUsage();
            if (anchor.getBasicConstraints() < 0 || (keyUsage != null && (keyUsage.length < 6 || !keyUsage[5]))) {
                throw invalid();
            }
            trust.setCertificateEntry("ca-" + i, anchor);
        }
        return trust;
    }

    private static void requireServerPath(List<X509Certificate> chain, List<X509Certificate> anchors)
            throws GeneralSecurityException {
        var trusted = new java.util.HashSet<TrustAnchor>();
        for (var anchor : anchors) {
            trusted.add(new TrustAnchor(anchor, null));
        }
        var path = new ArrayList<X509Certificate>();
        for (var certificateInPath : chain) {
            if (anchors.contains(certificateInPath)) {
                break;
            }
            path.add(certificateInPath);
        }
        var parameters = new PKIXParameters(trusted);
        parameters.setRevocationEnabled(false);
        CertPathValidator
                .getInstance("PKIX")
                .validate(CertificateFactory.getInstance("X.509").generateCertPath(path), parameters);
    }

    private static void requireP256(java.security.Key key) throws GeneralSecurityException {
        if (!(key instanceof ECKey ec)) {
            throw invalid();
        }
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
        ECParameterSpec actual = ec.getParams();
        if (actual == null || !actual.getCurve().equals(expected.getCurve())
                || !actual.getGenerator().equals(expected.getGenerator())
                || !actual.getOrder().equals(expected.getOrder()) || actual.getCofactor() != expected.getCofactor()) {
            throw invalid();
        }
    }

    private static List<X509Certificate> certificates(byte[] bytes) throws GeneralSecurityException {
        var certificates = new ArrayList<X509Certificate>();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (byte[] der : pem(bytes, "CERTIFICATE")) {
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
            certificate.checkValidity();
            certificates.add(certificate);
        }
        return certificates;
    }

    private static List<byte[]> pem(byte[] bytes, String label) throws GeneralSecurityException {
        String remaining = new String(bytes, StandardCharsets.US_ASCII).strip();
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        var result = new ArrayList<byte[]>();
        while (!remaining.isEmpty()) {
            if (result.size() == 16 || !remaining.startsWith(begin)) {
                throw invalid();
            }
            int closing = remaining.indexOf(end, begin.length());
            if (closing < 0) {
                throw invalid();
            }
            String encoded = remaining.substring(begin.length(), closing).replace("\r", "").replace("\n", "");
            try {
                result.add(Base64.getDecoder().decode(encoded));
            } catch (IllegalArgumentException malformed) {
                throw invalid();
            }
            remaining = remaining.substring(closing + end.length()).strip();
        }
        if (result.isEmpty()) {
            throw invalid();
        }
        return result;
    }

    private static BasicFileAttributes attributes(Path path) throws IOException, GeneralSecurityException {
        BasicFileAttributes state = Files.readAttributes(path, BasicFileAttributes.class);
        if (!state.isRegularFile() || state.size() <= 0 || state.size() > MAX_FILE_BYTES) {
            throw invalid();
        }
        return state;
    }

    private static byte[] read(Path path) throws IOException, GeneralSecurityException {
        try (var input = Files.newInputStream(path)) {
            byte[] bytes = input.readNBytes(MAX_FILE_BYTES + 1);
            if (bytes.length == 0 || bytes.length > MAX_FILE_BYTES) {
                throw invalid();
            }
            return bytes;
        }
    }

    private static void unchanged(Path logical, Path resolved, BasicFileAttributes before)
            throws IOException, GeneralSecurityException {
        BasicFileAttributes after = attributes(resolved);
        if (!logical.toRealPath().equals(resolved) || !java.util.Objects.equals(before.fileKey(), after.fileKey())
                || before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())) {
            throw invalid();
        }
    }

    private static GeneralSecurityException invalid() {
        return new GeneralSecurityException("IDENTITY_UNAVAILABLE");
    }
}
