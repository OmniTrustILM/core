package com.otilm.core.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.FileSystemResource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Asserts that no shipped configuration turns on Hibernate's bound-parameter logging.
 *
 * <p>
 * {@code org.hibernate.orm.jdbc.bind} at TRACE prints every value bound to every statement. Among those values is
 * {@code crypto_asset.identity_key}, whose whole protection is that it never leaves the database: a log line is the
 * same disclosure as a response field, and logs travel further. The rule covers the ancestors too -- a root logger at
 * TRACE enables the binding logger just as surely as naming it does.
 *
 * <p>
 * Every shipped YAML, properties and XML file is read, not one named file: a level set in a second logback profile, a
 * properties file, or a configuration this test has never heard of enables the logger exactly as well as the one this
 * test used to know about. The XML is <b>parsed</b> rather than pattern-matched, because a level is reachable through
 * spellings no regular expression anticipates -- attribute order, a {@code <level value="TRACE"/>} child element, a
 * logger nested inside a conditional block. The parser sees all of them; a line scan sees the shapes it was written
 * for.
 *
 * <p>
 * Deploy-time overrides are outside this test's reach; what it can and does pin is that nothing we ship, and no default
 * of an environment variable we ship, arrives at TRACE.
 */
class HibernateBindingLogConfigTest {

    private static final Path SHIPPED_CONFIG_ROOT = Path.of("src/main/resources");

    private static final Path LOGBACK_CONFIG = Path.of("src/main/resources/logback-spring.xml");

    private static final String LOGGING_LEVEL_PREFIX = "logging.level.";

    /** Loggers that print bound parameters: the Hibernate 6 name, and the Hibernate 5 name still seen in the wild. */
    private static final List<String> BINDING_LOGGERS = List
            .of("org.hibernate.orm.jdbc.bind", "org.hibernate.type.descriptor.sql.BasicBinder");

    private static final String HIBERNATE_ROOT = "org.hibernate";

    private static final Set<String> LEVELS_THAT_PRINT_BINDINGS = Set.of("TRACE", "ALL", "UNRESOLVED");

    /**
     * {@code ${ENV_VAR:default}} and logback's own {@code ${ENV_VAR:-default}} -- what matters is the default, which is
     * what ships. Both spellings are accepted because a logback file is the one place the {@code :-} form is the
     * documented syntax, and reading it as the literal default {@code -TRACE} let a shipped TRACE default pass.
     */
    private static final Pattern PLACEHOLDER = Pattern.compile("^\\$\\{[^:}]*(?::-?(.*))?}$");

    /**
     * The level of a placeholder with no default. It cannot be known here, so it is treated as printing: the fence
     * fails closed, as it already does for a document it cannot parse. A configuration whose effective level depends on
     * the environment is exactly the one nobody can certify does not ship TRACE.
     */
    private static final String UNRESOLVED = "UNRESOLVED";

    // ---- the rule ----

    /**
     * Whether a logger configured at TRACE could put a bound parameter in a log.
     *
     * <p>
     * True for the binding loggers themselves, for every ancestor of one (root included), and for anything below one.
     * True also for anything else inside {@code org.hibernate}: the rule is stated over the whole Hibernate tree rather
     * than the two exact logger names, because a TRACE level inside persistence is never worth the risk of a renamed
     * category, and drawing the line finely is how a fence acquires a hole.
     */
    static boolean mayPrintBoundParameters(String loggerName) {
        String logger = loggerName == null || loggerName.isBlank() || "root".equalsIgnoreCase(loggerName)
                ? ""
                : loggerName.trim();
        if (logger.isEmpty()) {
            return true;
        }
        if (logger.equals(HIBERNATE_ROOT) || logger.startsWith(HIBERNATE_ROOT + ".")) {
            return true;
        }
        return BINDING_LOGGERS.stream().anyMatch(target -> target.startsWith(logger + "."));
    }

    /** The configured level as shipped: a placeholder resolves to its default, and the comparison is locale-free. */
    static String shippedLevel(String rawValue) {
        if (rawValue == null) {
            return "";
        }
        Matcher placeholder = PLACEHOLDER.matcher(rawValue.trim());
        if (!placeholder.matches()) {
            return rawValue.trim().toUpperCase(Locale.ROOT);
        }
        String fallback = placeholder.group(1);
        return fallback == null || fallback.isBlank() ? UNRESOLVED : fallback.trim().toUpperCase(Locale.ROOT);
    }

    static List<String> bindingLogViolations(String source, Map<String, String> loggerLevels) {
        List<String> violations = new ArrayList<>();
        loggerLevels.forEach((logger, rawLevel) -> {
            String level = shippedLevel(rawLevel);
            if (LEVELS_THAT_PRINT_BINDINGS.contains(level) && mayPrintBoundParameters(logger)) {
                violations
                        .add(source + " sets logger '" + logger + "' to "
                                + (UNRESOLVED.equals(level)
                                        ? "a placeholder with no default, whose effective level cannot be known here"
                                        : level + ", which prints every bound parameter"));
            }
        });
        return violations;
    }

    // ---- the rule, applied to what ships ----

    @Test
    void noShippedConfigurationEnablesBoundParameterLogging() throws IOException {
        List<String> violations = new ArrayList<>();
        try (Stream<Path> files = Files.walk(SHIPPED_CONFIG_ROOT)) {
            for (Path file : files.filter(Files::isRegularFile).sorted().toList()) {
                violations.addAll(bindingLogViolations(file.toString(), configuredLevelsOf(file, violations)));
            }
        }

        assertThat(violations)
                .describedAs("a bound-parameter log line discloses the crypto-asset identity key as surely as a "
                        + "response field does")
                .isEmpty();
    }

    /**
     * The shipped logback configuration is read specifically, so that a walk which somehow matched nothing cannot pass
     * for a clean result. A fence over an empty set of files is green and means nothing.
     */
    @Test
    void logbackDoesNotEnableBoundParameterLogging() throws IOException {
        Map<String, String> levels = logbackLevels(Files.readString(LOGBACK_CONFIG, StandardCharsets.UTF_8));

        assertThat(levels).describedAs("the logback configuration must declare at least the root level").isNotEmpty();
        assertThat(bindingLogViolations(LOGBACK_CONFIG.toString(), levels)).isEmpty();
    }

    // ---- the rule, shown able to fail ----

    @Test
    void aPlantedBindingLoggerIsReported() {
        assertThat(bindingLogViolations("planted.yml", Map.of("org.hibernate.orm.jdbc.bind", "TRACE"))).hasSize(1);
        assertThat(bindingLogViolations("planted.yml", Map.of("org.hibernate", "trace"))).hasSize(1);
        assertThat(bindingLogViolations("planted.yml", Map.of("org", "TRACE"))).hasSize(1);
        assertThat(bindingLogViolations("planted.yml", Map.of("root", "TRACE"))).hasSize(1);
        assertThat(bindingLogViolations("planted.yml", Map.of("org.hibernate.SQL", "${LOG_LEVEL:ALL}"))).hasSize(1);
        assertThat(bindingLogViolations("planted.yml", Map.of("org.hibernate.orm", "TRACE"))).hasSize(1);
    }

    @Test
    void legitimateLevelsAreNotReported() {
        assertThat(bindingLogViolations("planted.yml", Map.of("org.hibernate", "WARN"))).isEmpty();
        assertThat(bindingLogViolations("planted.yml", Map.of("org.hibernate.SQL", "DEBUG"))).isEmpty();
        assertThat(bindingLogViolations("planted.yml", Map.of("com.otilm", "TRACE")))
                .describedAs("our own loggers at TRACE do not print Hibernate's bindings")
                .isEmpty();
        assertThat(bindingLogViolations("planted.yml", Map.of("com.otilm", "${PLATFORM_LOG_LEVEL:INFO}"))).isEmpty();
    }

    /**
     * The parser is planted through, not around. Each document below is a spelling the previous line-scanning rule read
     * as clean: the level in a child element rather than an attribute, the attributes in the other order, the logger
     * buried inside a conditional block, the root level as a child. A fence that cannot be shown to fail on the shapes
     * it was widened for is not evidence that they are covered.
     */
    @Test
    void aPlantedLogbackDocumentIsReported() {
        assertThat(violationsIn("""
                <configuration>
                  <logger name="org.hibernate.orm.jdbc.bind" level="TRACE"/>
                </configuration>
                """)).hasSize(1);
        assertThat(violationsIn("""
                <configuration>
                  <logger level="TRACE" name="org.hibernate"/>
                </configuration>
                """)).describedAs("attribute order is the parser's business, not the fence's").hasSize(1);
        assertThat(violationsIn("""
                <configuration>
                  <logger name="org.hibernate.orm.jdbc.bind" level="${BIND_LEVEL:-TRACE}"/>
                </configuration>
                """)).describedAs("logback's own default syntax ships the default just as Spring's does").hasSize(1);
        assertThat(violationsIn("""
                <configuration>
                  <logger name="org.hibernate.orm.jdbc.bind" level="${BIND_LEVEL}"/>
                </configuration>
                """))
                .describedAs("a placeholder with no default is unknowable here, so the fence fails closed")
                .hasSize(1);
        assertThat(violationsIn("""
                <configuration>
                  <logger name="org.hibernate.orm.jdbc.bind" level="${BIND_LEVEL:-INFO}"/>
                </configuration>
                """)).describedAs("a non-printing default in the same syntax still passes").isEmpty();
        assertThat(violationsIn("""
                <configuration>
                  <logger name="org.hibernate.orm.jdbc.bind">
                    <level value="TRACE"/>
                  </logger>
                </configuration>
                """)).describedAs("logback accepts the level as a child element").hasSize(1);
        assertThat(violationsIn("""
                <configuration>
                  <springProfile name="dev">
                    <logger name="org.hibernate" level="ALL"/>
                  </springProfile>
                </configuration>
                """)).describedAs("a logger nested in a profile block ships too").hasSize(1);
        assertThat(violationsIn("""
                <configuration>
                  <root>
                    <level value="TRACE"/>
                  </root>
                </configuration>
                """)).describedAs("a root at TRACE enables the binding logger").hasSize(1);
    }

    @Test
    void aCleanLogbackDocumentIsNotReported() {
        assertThat(violationsIn("""
                <configuration>
                  <logger name="com.otilm" level="DEBUG"/>
                  <logger name="org.hibernate.SQL" level="DEBUG"/>
                  <root level="INFO"/>
                </configuration>
                """)).isEmpty();
    }

    @Test
    void aPlantedPropertiesFileIsReported() {
        assertThat(bindingLogViolations("planted.properties",
                propertiesLevels("logging.level.org.hibernate.orm.jdbc.bind=TRACE\n"))).hasSize(1);
        assertThat(bindingLogViolations("planted.properties", propertiesLevels("logging.level.com.otilm=TRACE\n")))
                .isEmpty();
    }

    // ---- extraction ----

    /**
     * Every logger level the file declares, whatever kind of file it is. A file whose kind carries no logger levels
     * contributes nothing; a file whose kind does, but which cannot be read, is reported rather than skipped -- a fence
     * that treats an unreadable configuration as a clean one is the hole it exists to close.
     */
    private static Map<String, String> configuredLevelsOf(Path file, List<String> violations) throws IOException {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".yml") || name.endsWith(".yaml")) {
            return yamlLevels(file);
        }
        if (name.endsWith(".properties")) {
            return propertiesLevels(Files.readString(file, StandardCharsets.UTF_8));
        }
        if (name.endsWith(".xml")) {
            try {
                return logbackLevels(Files.readString(file, StandardCharsets.UTF_8));
            } catch (IOException e) {
                violations.add(file + " could not be parsed, so its logger levels are unknown");
                return Map.of();
            }
        }
        return Map.of();
    }

    private static Map<String, String> yamlLevels(Path yaml) {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new FileSystemResource(yaml));
        factory.afterPropertiesSet();
        return loggingLevelProperties(factory.getObject());
    }

    private static Map<String, String> propertiesLevels(String text) {
        Properties properties = new Properties();
        try (InputStream in = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8))) {
            properties.load(in);
        } catch (IOException e) {
            throw new IllegalStateException("in-memory properties failed to load", e);
        }
        return loggingLevelProperties(properties);
    }

    private static Map<String, String> loggingLevelProperties(Properties properties) {
        Map<String, String> levels = new LinkedHashMap<>();
        if (properties == null) {
            return levels;
        }
        properties
                .stringPropertyNames()
                .stream()
                .filter(key -> key.startsWith(LOGGING_LEVEL_PREFIX))
                .forEach(key -> levels.put(key.substring(LOGGING_LEVEL_PREFIX.length()), properties.getProperty(key)));
        return levels;
    }

    private static List<String> violationsIn(String xml) throws IllegalStateException {
        try {
            return bindingLogViolations("planted.xml", logbackLevels(xml));
        } catch (IOException e) {
            throw new IllegalStateException("planted document did not parse", e);
        }
    }

    /**
     * Every {@code <logger>} and {@code <root>} in the document, at any depth, with its level taken from the attribute
     * or from a {@code <level>} child. Depth matters: logback nests loggers inside {@code <springProfile>},
     * {@code <if>} and {@code <then>}, and a nested one ships exactly as much as a top-level one.
     *
     * <p>
     * A document that is not a logback configuration yields nothing, which is the correct answer for the many other XML
     * files under the resource root.
     */
    static Map<String, String> logbackLevels(String xml) throws IOException {
        Document document = parse(xml);
        Map<String, String> levels = new LinkedHashMap<>();
        if (document == null || document.getDocumentElement() == null) {
            return levels;
        }
        collectLevels(document.getDocumentElement(), levels);
        return levels;
    }

    private static void collectLevels(Element element, Map<String, String> levels) {
        String tag = localName(element);
        if ("logger".equals(tag) || "root".equals(tag)) {
            String name = "root".equals(tag) ? "root" : element.getAttribute("name");
            String level = element.hasAttribute("level") ? element.getAttribute("level") : childLevel(element);
            if (level != null && !level.isBlank()) {
                levels.put(name == null || name.isBlank() ? "root" : name, level);
            }
        }
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child instanceof Element childElement) {
                collectLevels(childElement, levels);
            }
        }
    }

    /** {@code <logger name="x"><level value="TRACE"/></logger>} -- logback's other spelling of the same thing. */
    private static String childLevel(Element element) {
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i) instanceof Element child && "level".equals(localName(child))) {
                return child.hasAttribute("value") ? child.getAttribute("value") : child.getTextContent();
            }
        }
        return null;
    }

    private static String localName(Element element) {
        String local = element.getLocalName() == null ? element.getTagName() : element.getLocalName();
        return local.toLowerCase(Locale.ROOT);
    }

    /**
     * Parses without resolving anything external: this reads shipped files to decide a security property, so an
     * external entity must not be able to make the parser fetch a URL or read a file off the box.
     */
    private static Document parse(String xml) throws IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder
                    .setEntityResolver(
                            (publicId, systemId) -> new org.xml.sax.InputSource(new java.io.StringReader("")));
            return builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("the document could not be parsed", e);
        }
    }
}
