package com.otilm.core.settings.branding;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Strips everything executable or externally referencing out of an operator-supplied SVG logo.
 *
 * <p>
 * Branding logos are stored by the platform and rendered on the login page to visitors who have not authenticated, so
 * an SVG logo is the highest-exposure input the branding feature accepts. The frontend renders logos through an
 * {@code img} element, where browsers already refuse to run script or fetch external resources; this sanitizer is the
 * server-side half, so that a logo is safe even if something later inlines it into the page.
 *
 * <p>
 * Elements are handled by allow-list rather than by removing the dangerous ones. A deny-list only ever covers the
 * attacks known when it was written — {@code script} and {@code foreignObject} are the obvious two, but {@code
 * animate} can rewrite an attribute after load and {@code handler} exists in SVG 1.2 — whereas an allow-list of drawing
 * constructs is safe against constructs nobody here has heard of yet.
 */
public final class SvgSanitizer {

    /** Drawing constructs and their supporting definitions. Anything not on this list is dropped with its subtree. */
    private static final Set<String> ALLOWED_ELEMENTS = Set
            .of("svg", "g", "defs", "symbol", "use", "switch", "a", "title", "desc", "metadata", "style", "path",
                    "rect", "circle", "ellipse", "line", "polyline", "polygon", "text", "tspan", "textPath", "image",
                    "marker", "mask", "clipPath", "pattern", "linearGradient", "radialGradient", "stop", "filter",
                    "feBlend", "feColorMatrix", "feComponentTransfer", "feComposite", "feConvolveMatrix",
                    "feDiffuseLighting", "feDisplacementMap", "feDistantLight", "feDropShadow", "feFlood", "feFuncA",
                    "feFuncB", "feFuncG", "feFuncR", "feGaussianBlur", "feImage", "feMerge", "feMergeNode",
                    "feMorphology", "feOffset", "fePointLight", "feSpecularLighting", "feSpotLight", "feTile",
                    "feTurbulence");

    /**
     * A reference the document can resolve on its own. Anything else — an absolute URL, a {@code javascript:} scheme, a
     * nested {@code data:} payload — is a way out of the document and is removed rather than inspected further.
     */
    private static final Pattern LOCAL_REFERENCE = Pattern.compile("^#[^\\s]*$");

    /** {@code url(#gradient)} is a reference within the same document; {@code url(https://…)} is not. */
    private static final Pattern EXTERNAL_CSS_REFERENCE = Pattern
            .compile("url\\(\\s*['\"]?\\s*(?!#)", Pattern.CASE_INSENSITIVE);

    private static final Pattern CSS_IMPORT = Pattern.compile("@import", Pattern.CASE_INSENSITIVE);

    private static final Set<String> REFERENCE_ATTRIBUTES = Set.of("href", "xlink:href", "src");

    private SvgSanitizer() {
    }

    /**
     * Removes every construct that could execute or reach outside the document, in place.
     *
     * @param document the parsed logo; mutated rather than copied, since the caller has just parsed it for this
     */
    public static void sanitize(Document document) {
        removeProcessingInstructions(document);
        sanitizeElement(document.getDocumentElement());
    }

    /** {@code <?xml-stylesheet href="…"?>} sits outside the root element and would otherwise survive the walk. */
    private static void removeProcessingInstructions(Document document) {
        NodeList nodes = document.getChildNodes();
        List<Node> topLevel = new ArrayList<>(nodes.getLength());
        for (int i = 0; i < nodes.getLength(); i++) {
            topLevel.add(nodes.item(i));
        }
        topLevel
                .stream()
                .filter(node -> node.getNodeType() == Node.PROCESSING_INSTRUCTION_NODE)
                .forEach(document::removeChild);
    }

    private static void sanitizeElement(Element element) {
        sanitizeAttributes(element);

        if ("style".equals(localName(element))) {
            element.setTextContent(sanitizeCss(element.getTextContent()));
            return;
        }

        // Copied out first: removing a child while iterating a live NodeList skips its successor.
        List<Node> children = childrenOf(element);
        for (Node child : children) {
            if (child instanceof Element childElement) {
                if (ALLOWED_ELEMENTS.contains(localName(childElement))) {
                    sanitizeElement(childElement);
                } else {
                    element.removeChild(childElement);
                }
            }
        }
    }

    private static List<Node> childrenOf(Element element) {
        NodeList nodes = element.getChildNodes();
        List<Node> children = new ArrayList<>(nodes.getLength());
        for (int i = 0; i < nodes.getLength(); i++) {
            children.add(nodes.item(i));
        }
        return children;
    }

    private static void sanitizeAttributes(Element element) {
        NamedNodeMap attributes = element.getAttributes();
        List<Attr> declared = new ArrayList<>(attributes.getLength());
        for (int i = 0; i < attributes.getLength(); i++) {
            declared.add((Attr) attributes.item(i));
        }

        for (Attr attribute : declared) {
            String name = attribute.getName().toLowerCase(Locale.ROOT);
            if (name.startsWith("on") || isRejectedReference(name, attribute.getValue())) {
                element.removeAttributeNode(attribute);
            } else if ("style".equals(name)) {
                attribute.setValue(sanitizeCss(attribute.getValue()));
            }
        }
    }

    /**
     * One rule covers {@code javascript:} and {@code data:} URLs and every external resource reference at once: a
     * reference is kept only when it points inside this document.
     */
    private static boolean isRejectedReference(String name, String value) {
        return REFERENCE_ATTRIBUTES.contains(name) && !LOCAL_REFERENCE.matcher(value.trim()).matches();
    }

    /** CSS can fetch too, through {@code @import} and {@code url()}, so both are removed from style declarations. */
    private static String sanitizeCss(String css) {
        if (css == null || css.isBlank()) {
            return css;
        }
        if (CSS_IMPORT.matcher(css).find() || EXTERNAL_CSS_REFERENCE.matcher(css).find()) {
            return "";
        }
        return css;
    }

    /** Serializes the sanitized document back to XML, so that only the sanitized form is ever stored. */
    public static String serialize(Document document) throws TransformerException {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");

        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));
        return writer.toString();
    }

    private static String localName(Element element) {
        return element.getLocalName() == null ? element.getNodeName() : element.getLocalName();
    }
}
