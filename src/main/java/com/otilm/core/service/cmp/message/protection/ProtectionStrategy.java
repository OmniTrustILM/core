package com.otilm.core.service.cmp.message.protection;

import com.otilm.api.interfaces.core.cmp.error.CmpConfigurationException;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

import java.util.List;

public interface ProtectionStrategy {

    /**
     * @return protection algorithm for {@link PKIMessage#getProtection()} (for outgoing/response part)
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#appendix-D.2">Algorithm Use Profile</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9481.html">Certificate Management Protocol (CMP) Algorithms</a>
     */
    AlgorithmIdentifier getProtectionAlg() throws CmpConfigurationException;

    /**
     * create {@link PKIMessage} protection string using {@link ProtectedPart}
     * <pre>
     *         ProtectedPart ::= SEQUENCE {
     *             header    PKIHeader,
     *             body      PKIBody
     *         }
     * </pre>
     *
     * @param header part for protection
     * @param body   part for protection
     * @return the protection string
     * @throws Exception in case of error
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3">PKI Message Protection</a>
     */
    DERBitString createProtection(PKIHeader header, PKIBody body) throws Exception;

    List<CMPCertificate> getProtectingExtraCerts() throws Exception;

    /**
     * @return sender to use for protected message
     */
    GeneralName getSender();

    /**
     * <p>The sender field contains the name of the sender of the PKIMessage.
     * This name (in conjunction with senderKID, if supplied) should be
     * sufficient to indicate the key to use to verify the protection on the
     * message.  If nothing about the sender is known to the sending entity
     * (e.g., in the init. req. message, where the end entity may not know
     * its own Distinguished Name (DN), e-mail name, IP address, etc.), then
     * the "sender" field MUST contain a "NULL" value; that is, the SEQUENCE
     * OF relative distinguished names is of zero length.  In such a case,
     * the senderKID field MUST hold an identifier (i.e., a reference
     * number) that indicates to the receiver the appropriate shared secret
     * information to use to verify the message.</p>
     *
     * <p>The recipient field contains the name of the recipient of the
     * PKIMessage.  This name (in conjunction with recipKID, if supplied)
     * should be usable to verify the protection on the message.</p>
     *
     * <p>The protectionAlg field specifies the algorithm used to protect the
     * message.  If no protection bits are supplied (note that PKIProtection
     * is OPTIONAL) then this field MUST be omitted; if protection bits are
     * supplied, then this field MUST be supplied.</p>
     *
     * <p>senderKID and recipKID are usable to indicate which keys have been
     * used to protect the message (recipKID will normally only be required
     * where protection of the message uses Diffie-Hellman (DH) keys).</p>
     *
     * <p>These fields MUST be used if required to uniquely identify a key
     * (e.g., if more than one key is associated with a given sender name)
     * and SHOULD be omitted otherwise.</p>
     * <p>
     * mac - config.getSenderKID
     * sig - get from last cert in chain;
     *
     * @return sender KID to use for protected message
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1">PKIHeader field</a>
     */
    ASN1OctetString getSenderKID();
}
