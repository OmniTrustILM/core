package com.otilm.core.settings.branding;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
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
 * Elements are handled by allow-list rather than by removing the dangerous ones, because a deny-list only ever covers
 * the attacks known when it was written — {@code animate} rewrites an attribute after load and {@code handler} exists
 * in SVG 1.2 — whereas an allow-list of drawing constructs holds against constructs nobody here has heard of yet.
 * Attributes are the mirror image, since a logo needs an open-ended set of them: everything is kept except what
 * executes, rebases or fetches, and whether a value fetches is decided after CSS escapes are resolved.
 */
public final class SvgSanitizer {

    /** Names both the {@code <style>} element and the {@code style} attribute, the two places a logo carries CSS. */
    private static final String STYLE = "style";

    /** Drawing constructs and their supporting definitions. Anything not on this list is dropped with its subtree. */
    private static final Set<String> ALLOWED_ELEMENTS = Set
            .of("svg", "g", "defs", "symbol", "use", "switch", "a", "title", "desc", "metadata", STYLE, "path", "rect",
                    "circle", "ellipse", "line", "polyline", "polygon", "text", "tspan", "textPath", "image", "marker",
                    "mask", "clipPath", "pattern", "linearGradient", "radialGradient", "stop", "filter", "feBlend",
                    "feColorMatrix", "feComponentTransfer", "feComposite", "feConvolveMatrix", "feDiffuseLighting",
                    "feDisplacementMap", "feDistantLight", "feDropShadow", "feFlood", "feFuncA", "feFuncB", "feFuncG",
                    "feFuncR", "feGaussianBlur", "feImage", "feMerge", "feMergeNode", "feMorphology", "feOffset",
                    "fePointLight", "feSpecularLighting", "feSpotLight", "feTile", "feTurbulence");

    /**
     * A reference the document can resolve on its own. Anything else — an absolute URL, a {@code javascript:} scheme, a
     * nested {@code data:} payload — is a way out of the document and is removed rather than inspected further. A
     * fragment cannot name another document once {@code xml:base} is gone, which is why that is stripped as well.
     */
    private static final Pattern LOCAL_REFERENCE = Pattern.compile("^#[^\\s]*$");

    /**
     * {@code url(#gradient)} is a reference within the same document; {@code url(https://…)} is not. The quantifiers
     * are possessive so that the engine cannot backtrack over consumed whitespace or an opening quote to make the
     * lookahead succeed, which would report {@code url( #gradient)} and {@code url('#gradient')} as external.
     */
    private static final Pattern EXTERNAL_URL_FUNCTION = Pattern
            .compile("url\\(\\s*+['\"]?+\\s*+(?!#)", Pattern.CASE_INSENSITIVE);

    private static final Pattern CSS_IMPORT = Pattern.compile("@import", Pattern.CASE_INSENSITIVE);

    /**
     * {@code image-set()} accepts a bare string as well as a {@code url()}, so it fetches without matching the above.
     */
    private static final Pattern CSS_IMAGE_SET = Pattern.compile("image-set\\s*+\\(", Pattern.CASE_INSENSITIVE);

    /**
     * A CSS escape: a backslash and up to six hex digits naming a code point, closed by one optional whitespace
     * character, or a backslash and one literal character. Escapes are legal anywhere a CSS value is parsed, which
     * includes SVG presentation attributes, so {@code \75 rl(…)} tokenizes as {@code url(…)}.
     */
    private static final Pattern CSS_ESCAPE = Pattern.compile("\\\\(?:([0-9a-fA-F]{1,6})\\s?|(.))", Pattern.DOTALL);

    /**
     * Matched on local name alone rather than on the qualified name, so that every prefix bound to the XLink namespace
     * is covered: {@code xlink:href} is only the conventional spelling, and {@code xl:href} means the same thing.
     */
    private static final Set<String> REFERENCE_ATTRIBUTES = Set.of("href", "src");

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

        if (STYLE.equals(localName(element))) {
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
            String name = localName(attribute).toLowerCase(Locale.ROOT);
            if (STYLE.equals(name)) {
                attribute.setValue(sanitizeCss(attribute.getValue()));
            } else if (isRejected(attribute, name)) {
                element.removeAttributeNode(attribute);
            }
        }
    }

    /**
     * Event handlers execute; {@code xml:base} rebases every relative reference in its subtree, so a kept {@code #id}
     * is only same-document once it is gone; a reference attribute is a way out of the document unless it points back
     * into it. Anything else is a presentation attribute, whose value is parsed as CSS and can carry a fetching
     * {@code url()} of its own — {@code fill}, {@code stroke}, {@code filter}, {@code mask}, {@code clip-path} and the
     * {@code marker-*} family all take one — so the {@code url()} rule is applied to every remaining attribute rather
     * than to a list of the ones that accept a functional IRI today.
     */
    private static boolean isRejected(Attr attribute, String name) {
        if (isNamespaceDeclaration(attribute)) {
            return false;
        }

        String value = attribute.getValue();
        return name.startsWith("on") || isXmlBase(attribute, name)
                || (REFERENCE_ATTRIBUTES.contains(name) && !LOCAL_REFERENCE.matcher(value.trim()).matches())
                || EXTERNAL_URL_FUNCTION.matcher(decodeCssEscapes(value)).find();
    }

    /**
     * {@code xmlns} and {@code xmlns:*} carry namespace URIs that are not references to fetch, and dropping one would
     * unbind a prefix the document still uses.
     */
    private static boolean isNamespaceDeclaration(Attr attribute) {
        return XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attribute.getNamespaceURI());
    }

    /** Matched by namespace URI, since the {@code xml} prefix is only the spelling the declaration-free form uses. */
    private static boolean isXmlBase(Attr attribute, String name) {
        return "base".equals(name) && XMLConstants.XML_NS_URI.equals(attribute.getNamespaceURI());
    }

    /**
     * CSS fetches through {@code @import}, {@code url()} and {@code image-set()}, and can spell any of them with
     * escapes, so the decision is taken on the unescaped text and the whole declaration is dropped on a match. Only the
     * decision uses the unescaped copy: what survives is the original text, unmodified.
     */
    private static String sanitizeCss(String css) {
        if (css == null || css.isBlank()) {
            return css;
        }
        String decoded = decodeCssEscapes(css);
        boolean fetches = CSS_IMPORT.matcher(decoded).find() || EXTERNAL_URL_FUNCTION.matcher(decoded).find()
                || CSS_IMAGE_SET.matcher(decoded).find();
        return fetches ? "" : css;
    }

    /**
     * Resolves CSS escapes, so that a token written {@code \75 rl(} is compared as {@code url(}. Used only to decide
     * whether a value fetches; no value is ever rewritten from the result.
     */
    private static String decodeCssEscapes(String value) {
        if (value.indexOf('\\') < 0) {
            return value;
        }

        Matcher matcher = CSS_ESCAPE.matcher(value);
        StringBuilder decoded = new StringBuilder(value.length());
        while (matcher.find()) {
            matcher.appendReplacement(decoded, "");
            String hex = matcher.group(1);
            if (hex == null) {
                decoded.append(matcher.group(2));
            } else {
                decoded.appendCodePoint(codePointOf(hex));
            }
        }
        matcher.appendTail(decoded);
        return decoded.toString();
    }

    /** CSS resolves an escape naming nothing addressable to the replacement character rather than failing to parse. */
    private static int codePointOf(String hex) {
        int codePoint = Integer.parseInt(hex, 16);
        boolean addressable = codePoint > 0 && codePoint <= Character.MAX_CODE_POINT
                && (codePoint < Character.MIN_SURROGATE || codePoint > Character.MAX_SURROGATE);
        return addressable ? codePoint : 0xFFFD;
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

    private static String localName(Node node) {
        return node.getLocalName() == null ? node.getNodeName() : node.getLocalName();
    }
}
