package com.otilm.core.service.cmp.message;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.anssi.ANSSIObjectIdentifiers;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.dvcs.DVCSObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.sigi.SigIObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A utility class providing functions for dumping messages.
 *
 * @author Andreas Kretschmer (cmp-ra-component/Apache 2.0 Licence)
 * @see <a href="https://github.com/siemens/cmp-ra-component/blob/main/src/main/java/com/siemens/pki/cmpracomponent/util/MessageDumper.java">...</a>
 */
public class PkiMessageDumper {

    private static final Logger LOG = LoggerFactory.getLogger(PkiMessageDumper.class.getName());
    private static final Map<Integer, String> TYPES = new ConcurrentHashMap<>();
    private static Map<ASN1ObjectIdentifier, OidDescription> oidToKeyMap;

    static {
        // load symbolic names defined in PKIBody
        for (final Field aktField : PKIBody.class.getFields()) {
            if (aktField.getType().equals(Integer.TYPE)
                    && (aktField.getModifiers() & Modifier.STATIC) != 0
                    && aktField.getName().startsWith("TYPE_")) {
                try {
                    TYPES.put(aktField.getInt(null), aktField.getName().substring(5));
                } catch (IllegalArgumentException | IllegalAccessException e) {
                    LOG.error("error filling typemap", e);
                }
            }
        }
    }

    public static void dumpSingerCertificate(String location,
                                             X509Certificate singerCertificate,
                                             CMPCertificate[] extraCerts) {
        if ("builder".equals(location)) {
            if (extraCerts != null && extraCerts.length > 0) {
                for (var i = 0; i < extraCerts.length; i++) {
                    org.bouncycastle.asn1.x509.Certificate cert = extraCerts[i].getX509v3PKCert();
                    LOG.info("{}", String.format("%s - [%s]\nsubject=%s, \nsn=%s, \nissuer=%s",
                            location.toUpperCase(),
                            i,
                            cert.getSubject(),
                            cert.getSerialNumber(),
                            cert.getIssuer()));
                }
            } else {
                LOG.info("extraCerts are empty");
            }
        } else {
            LOG.info("{}", String.format("%s - [%s]\nsubject=%s, \nsn=%s, \nissuer=%s",
                    location.toUpperCase(),
                    0,
                    singerCertificate.getSubjectX500Principal(),
                    singerCertificate.getSerialNumber(),
                    singerCertificate.getIssuerX500Principal()));
        }
    }

    /**
     * @param msg         source of data for log prefix
     * @param profileName next data for log prefix
     * @return short version of pki message (type, tid, profileName)
     */
    public static String logPrefix(PKIMessage msg, String profileName) {
        return String.format("%s TID=%s, PN=%s",
                PkiMessageDumper.msgTypeAsShortCut(true, msg),
                msg.getHeader().getTransactionID(),
                profileName);
    }

    /**
     * @param msg whose type is translated into shortcut, e.g. InitialRequest->ir
     * @return shortcut of given {@link PKIBody#getType()}
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.2">PKI Body overview</a>
     */
    public static String msgTypeAsShortCut(boolean showIndex, PKIMessage msg) {
        String format = showIndex ? "(%s:%s)" : "(%s)";
        int type = msg.getBody().getType();
        switch (type) {
            case PKIBody.TYPE_INIT_REQ -> {
                return String.format(format, "ir", type/* 0*/);
            }
            case PKIBody.TYPE_INIT_REP -> {
                return String.format(format, "ip", type/* 1*/);
            }
            case PKIBody.TYPE_CERT_REQ -> {
                return String.format(format, "cr", type/* 2*/);
            }
            case PKIBody.TYPE_CERT_REP -> {
                return String.format(format, "ip", type/* 3*/);
            }
            case PKIBody.TYPE_P10_CERT_REQ -> {
                return String.format(format, "p10cr", type/* 4*/);
            }
            case PKIBody.TYPE_POPO_CHALL -> {
                return String.format(format, "popdecc", type/* 5*/);
            }
            case PKIBody.TYPE_POPO_REP -> {
                return String.format(format, "popdecr", type/* 6*/);
            }
            case PKIBody.TYPE_KEY_UPDATE_REQ -> {
                return String.format(format, "kur", type/* 7*/);
            }
            case PKIBody.TYPE_KEY_UPDATE_REP -> {
                return String.format(format, "kup", type/* 8*/);
            }
            case PKIBody.TYPE_KEY_RECOVERY_REQ -> {
                return String.format(format, "krr", type/* 9*/);
            }
            case PKIBody.TYPE_KEY_RECOVERY_REP -> {
                return String.format(format, "krp", type/*10*/);
            }
            case PKIBody.TYPE_REVOCATION_REQ -> {
                return String.format(format, "rr", type/*11*/);
            }
            case PKIBody.TYPE_REVOCATION_REP -> {
                return String.format(format, "rp", type/*12*/);
            }
            case PKIBody.TYPE_CROSS_CERT_REQ -> {
                return String.format(format, "ccr", type/*13*/);
            }
            case PKIBody.TYPE_CROSS_CERT_REP -> {
                return String.format(format, "ccp", type/*14*/);
            }
            case PKIBody.TYPE_CA_KEY_UPDATE_ANN -> {
                return String.format(format, "ckuann", type/*15*/);
            }
            case PKIBody.TYPE_CERT_ANN -> {
                return String.format(format, "cann", type/*16*/);
            }
            case PKIBody.TYPE_REVOCATION_ANN -> {
                return String.format(format, "rann", type/*17*/);
            }
            case PKIBody.TYPE_CRL_ANN -> {
                return String.format(format, "crlann", type/*18*/);
            }
            case PKIBody.TYPE_CONFIRM -> {
                return String.format(format, "pkiconf", type/*19*/);
            }
            case PKIBody.TYPE_NESTED -> {
                return String.format(format, "nested", type/*20*/);
            }
            case PKIBody.TYPE_GEN_MSG -> {
                return String.format(format, "genm", type/*21*/);
            }
            case PKIBody.TYPE_GEN_REP -> {
                return String.format(format, "genp", type/*22*/);
            }
            case PKIBody.TYPE_ERROR -> {
                return String.format(format, "error", type/*23*/);
            }
            case PKIBody.TYPE_CERT_CONFIRM -> {
                return String.format(format, "certConf", type/*24*/);
            }
            case PKIBody.TYPE_POLL_REQ -> {
                return String.format(format, "pollReq", type/*25*/);
            }
            case PKIBody.TYPE_POLL_REP -> {
                return String.format(format, "pollRep", type/*26*/);
            }
        }
        return "<unknown-type>";
    }

    /**
     * @param verbose if true (=long version) otherwise short version of {@link PKIMessage}
     * @param msg     message for dump
     * @return return log version (short/long by given <code>verbose</code> flag) of {@link PKIMessage}
     */
    public static String dumpPkiMessage(boolean verbose, PKIMessage msg) {
        if (verbose) return dumpPkiMessage(msg);
        return " [" + msg.getHeader().getSender() + " => " + msg.getHeader().getRecipient() + "]";
    }

    /**
     * Dump PKI message to a string.
     *
     * @param msg PKI message to be dumped
     * @return string representation of the PKI message
     */
    public static String dumpPkiMessage(PKIMessage msg) {
        if (msg == null) {
            return "<null>";
        }
        final StringBuilder ret = new StringBuilder(10000);
        ret.append("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ");
        ret.append(msgTypeAsString(msg));
        ret.append(" message:\n");
        try {
            dumpSingleValue("Header", msg.getHeader(), ret);
            dumpSingleValue("Body", msg.getBody(), ret);
            dumpSingleValue("Protection", msg.getProtection(), ret);
            dumpSingleValue("ExtraCerts", msg.getExtraCerts(), ret);
        } catch (final Exception e) {
            LOG.error("dump error", e);
        }
        ret.append("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
        return ret.toString();
    }

    private static void dumpSingleValue(final String indent, final Object callRet, final StringBuilder ret)
            throws ParseException {
        if (callRet == null) {
            ret.append(indent);
            ret.append(":<absent>\n");
            return;
        }
        if (callRet.getClass().isArray()) {
            if (callRet instanceof byte[]) {
                ret.append(indent);
                ret.append(": ");
                ret.append(Arrays.toString((byte[]) callRet));
                ret.append("\n");
                return;
            }
            final Object[] callRetArray = (Object[]) callRet;
            if (callRetArray.length == 0) {
                ret.append(indent);
                ret.append(":[]\n");
                return;
            }
            for (int i = 0; i < callRetArray.length; i++) {
                final Object elem = callRetArray[i];
                dumpSingleValue(indent + "[" + i + "]", elem, ret);
            }
            return;
        }
        if (callRet instanceof Iterable<?> callRetCollection) {
            int i = 0;
            for (final Object elem : callRetCollection) {
                dumpSingleValue(indent + "[" + i++ + "]", elem, ret);
            }
            return;
        }
        if (callRet instanceof ASN1GeneralizedTime) {
            ret.append(indent).append(": ").append(((ASN1GeneralizedTime) callRet).getDate()).append("\n");
            return;
        }
        if (callRet instanceof ASN1ObjectIdentifier) {
            ret.append(indent).append(": ").append(getOidDescriptionForOid((ASN1ObjectIdentifier) callRet)).append("\n");
            return;
        }
        if (callRet instanceof PKIFreeText val) {
            final int size = val.size();
            if (size == 0) {
                ret.append(indent);
                ret.append(":[]\n");
                return;
            }
            for (int i = 0; i < size; i++) {
                ret.append(indent).append("[").append(i).append("] : ").append(val.getStringAtUTF8(i)).append("\n");
            }
            return;
        }
        if (callRet instanceof PollRepContent val) {
            final int size = val.size();
            if (size == 0) {
                ret.append(indent);
                ret.append(":[]\n");
                return;
            }
            for (int i = 0; i < size; i++) {
                dumpSingleValue(indent + "[" + i + "]/CertReqId: ", val.getCertReqId(i), ret);
                dumpSingleValue(indent + "[" + i + "]/Reason: ", val.getReason(i), ret);
                dumpSingleValue(indent + "[" + i + "]/CheckAfter: ", val.getCheckAfter(i), ret);
            }
            return;
        }
        if (callRet instanceof Extensions val) {
            final ASN1ObjectIdentifier[] extensionOIDs = val.getExtensionOIDs();
            final int size = extensionOIDs.length;
            if (size == 0) {
                ret.append(indent);
                ret.append(":[]\n");
                return;
            }
            for (int i = 0; i < size; i++) {
                final Extension ext = val.getExtension(extensionOIDs[i]);
                dumpSingleValue(
                        indent + "[" + i + "]/Id" + (ext.isCritical() ? "(critical)" : ""), ext.getExtnId(), ret);
                dumpSingleValue(indent + "[" + i + "]/Value", ext.getParsedValue(), ret);
            }
            return;
        }
        if (callRet instanceof ASN1Enumerated) {
            ret.append(indent).append(": ").append(((ASN1Enumerated) callRet).getValue()).append("\n");
            return;
        }
        if (callRet instanceof org.bouncycastle.asn1.ASN1Primitive
                || callRet instanceof GeneralName
                || callRet instanceof Number
                || callRet instanceof CharSequence
                || callRet instanceof X500Name
                || callRet instanceof Date) {
            ret.append(indent).append(": ").append(callRet).append("\n");
            return;
        }
        if (callRet instanceof ASN1Object) {
            dump(indent + "/", (ASN1Object) callRet, ret);
            return;
        }
        ret.append(indent);
        ret.append(": <could not decode, skipped> ==============\n");
    }

    /**
     * @param msg message to be dumped
     * @return short representation of the message
     */
    public static String msgAsShortString(final PKIMessage msg) {
        if (msg == null) {
            return "<null>";
        }
        return "tid=" + msg.getHeader().getTransactionID() + ": " + msgTypeAsString(msg.getBody()) + " [" + msg.getHeader().getSender() + " => "
                + msg.getHeader().getRecipient() + "]";
    }

    /**
     * Get message type from a PKI message body as string
     *
     * @param msgType PKI message type
     * @return message type as string
     */
    public static String msgTypeAsString(final int msgType) {
        return TYPES.get(msgType);
    }

    /**
     * Get message type from a PKI message body as string
     *
     * @param body PKI message body
     * @return message type as string
     */
    public static String msgTypeAsString(final PKIBody body) {
        return TYPES.get(body.getType());
    }

    /**
     * Get message type from a PKI message as string
     *
     * @param msg PKI message
     * @return message type as string
     */
    public static String msgTypeAsString(final PKIMessage msg) {
        if (msg == null) {
            return null;
        }
        return msgTypeAsString(msg.getBody());
    }

    private static void dump(final String indent, final ASN1Object object, final StringBuilder ret) {
        final List<String> nullMemberList = new ArrayList<>();
        for (final Method method : object.getClass().getMethods()) {
            if ((method.getModifiers() & Modifier.STATIC) != 0 || method.getParameterCount() != 0) {
                continue;
            }
            final Class<?> declaringClass = method.getDeclaringClass();
            if (declaringClass.equals(Object.class) || declaringClass.equals(ASN1Object.class)) {
                continue;
            }
            final String methodName = method.getName();
            try {
                final boolean isGetter = methodName.startsWith("get");
                final boolean isArray = methodName.startsWith("to") && methodName.endsWith("Array");
                if (!isGetter && !isArray) {
                    continue;
                }
                String memberName;
                if (isGetter) {
                    memberName = methodName.substring(3);
                } else {
                    memberName = methodName.substring(2).replace("Array", "");
                }
                final Object callRet = method.invoke(object);
                if (callRet == null) {
                    nullMemberList.add(memberName);
                    continue;
                }
                dumpSingleValue(indent + memberName, callRet, ret);
            } catch (final InvocationTargetException ex) {
                ret.append(indent).append(methodName).append(": ").append(ex.getTargetException().getMessage()).append(": <could not parse, skipped> ==============\n");
            } catch (final Exception ex) {
                ret.append(indent).append(methodName).append(":").append(ex.getMessage()).append(": <could not parse, skipped> ==============\n");
            }
        }
        if (!nullMemberList.isEmpty()) {
            ret.append(indent);
            ret.append('(');
            for (final String akt : nullMemberList) {
                ret.append(akt);
                ret.append('|');
            }
            ret.deleteCharAt(ret.length() - 1);
            ret.append("):<null>\n");
        }
    }

    public static class OidDescription {
        private final String id;
        private final String declaringPackage;
        private final ASN1ObjectIdentifier oid;
        private final Class<?> declaringClass;

        /**
         * Constructor for OID Descriptor class
         *
         * @param declaringClass declaring class of the OID
         * @param id             ID
         * @param oid            ASN.1 representation of the OID
         */
        public OidDescription(final Class<?> declaringClass, final String id, final ASN1ObjectIdentifier oid) {
            this.declaringPackage =
                    ifNotNull(declaringClass, x -> x.getSimpleName().replace("ObjectIdentifiers", ""));
            this.declaringClass = declaringClass;
            this.id = id;
            this.oid = oid;
        }

        /**
         * get declaring class
         *
         * @return declaring class
         */
        public String getBcDeclaration() {
            return ifNotNull(declaringClass, Class::getCanonicalName) + "." + id;
        }

        /**
         * Get declaring package of the OID
         *
         * @return declaring package of the OID
         */
        public String getDeclaringPackage() {
            return declaringPackage;
        }

        /**
         * Get ID
         *
         * @return ID
         */
        public String getId() {
            return id;
        }

        /**
         * Get ASN.1 representation of the OID
         *
         * @return ASN.1 representation of the OID
         */
        public ASN1ObjectIdentifier getOid() {
            return oid;
        }

        @Override
        public String toString() {
            return declaringPackage + "." + id + " (" + oid + ")";
        }
    }

    /**
     * load ObjectIdentifiers defined somewhere in BouncyCastle
     */
    private static synchronized void initNameOidMaps() {
        if (oidToKeyMap != null) {
            // already initialized
            return;
        }
        oidToKeyMap = new HashMap<>();
        for (final Class<?> aktClass : Arrays.asList(
                CMPObjectIdentifiers.class,
                PKCSObjectIdentifiers.class,
                X509ObjectIdentifiers.class,
                OIWObjectIdentifiers.class,
                CRMFObjectIdentifiers.class,
                CryptoProObjectIdentifiers.class,
                EACObjectIdentifiers.class,
                NISTObjectIdentifiers.class,
                ICAOObjectIdentifiers.class,
                ISISMTTObjectIdentifiers.class,
                SECObjectIdentifiers.class,
                ANSSIObjectIdentifiers.class,
                BCObjectIdentifiers.class,
                BSIObjectIdentifiers.class,
                CMSObjectIdentifiers.class,
                DVCSObjectIdentifiers.class,
                GNUObjectIdentifiers.class,
                IANAObjectIdentifiers.class,
                ISISMTTObjectIdentifiers.class,
                ISOIECObjectIdentifiers.class,
                KISAObjectIdentifiers.class,
                MicrosoftObjectIdentifiers.class,
                MiscObjectIdentifiers.class,
                NTTObjectIdentifiers.class,
                OCSPObjectIdentifiers.class,
                TeleTrusTObjectIdentifiers.class,
                UAObjectIdentifiers.class,
                ETSIQCObjectIdentifiers.class,
                RFC3739QCObjectIdentifiers.class,
                SigIObjectIdentifiers.class,
                X9ObjectIdentifiers.class,
                PQCObjectIdentifiers.class,
                org.bouncycastle.asn1.x509.Extension.class,
                EdECObjectIdentifiers.class,
                CMPObjectIdentifiers.class)) {
            for (final Field aktField : aktClass.getFields()) {
                if (aktField.getType().equals(ASN1ObjectIdentifier.class)
                        && (aktField.getModifiers() & Modifier.STATIC) != 0) {
                    try {
                        final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) aktField.get(null);
                        final String name = aktField.getName();
                        final OidDescription oidDescription = new OidDescription(aktClass, name, oid);
                        oidToKeyMap.put(oid, oidDescription);
                    } catch (IllegalArgumentException | IllegalAccessException e) {
                        LOG.error("error loading ObjectIdentifier Names from BC", e);
                    }
                }
            }
        }
    }

    /**
     * Get OID Description for a given OID (ASN.1 representation)
     *
     * @param oid OID (ASN.1 representation)
     * @return OID Description for a given OID (ASN.1 representation)
     */
    public static OidDescription getOidDescriptionForOid(final ASN1ObjectIdentifier oid) {
        initNameOidMaps();
        final OidDescription ret = oidToKeyMap.get(oid);
        if (ret == null) {
            return new OidDescription(null, "<unknown>", oid);
        }
        return ret;
    }

    /**
     * function with one argument throwing an exception
     *
     * @param <T> argument type
     * @param <R> result type
     * @param <E> exception type
     */
    public interface ExFunction<T, R, E extends Exception> {
        /**
         * execute function
         *
         * @param arg function argument
         * @return result
         * @throws E in case of error
         */
        R apply(T arg) throws E;
    }

    public static <R, V, E extends Exception> R ifNotNull(final V value, final ExFunction<V, R, E> function) throws E {
        try {
            return value == null ? null : function.apply(value);
        } catch (final NullPointerException npe) {
            return null;
        }
    }
}
