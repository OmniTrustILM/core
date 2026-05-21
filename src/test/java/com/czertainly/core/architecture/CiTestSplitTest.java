package com.czertainly.core.architecture;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the two-group CI test split defined in pom.xml.
 * <p>
 * The test-services Maven profile (<includes>) and the test-non-services profile (<excludes>)
 * must carry identical pattern sets. A pattern present in one but absent from the other
 * causes affected tests to run twice (double coverage noise) or not at all (silent gap).
 * <p>
 * Additionally, every concrete test class in the service package must follow the naming
 * convention those patterns match (*Test, *Tests, *ITest). Classes that don't match are
 * not picked up by test-services and run in test-non-services instead, silently misclassifying
 * service tests as non-service tests.
 */
class CiTestSplitTest {

    @Test
    void testServicesIncludesAndTestRestExcludesMustBeIdentical() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        Document pom = dbf.newDocumentBuilder().parse(Path.of("pom.xml").toFile());
        XPath xpath = XPathFactory.newDefaultInstance().newXPath();

        List<String> serviceIncludes = extractNodes(xpath, pom,
                "//profile[id='test-services']//plugin[artifactId='maven-surefire-plugin']//include");

        List<String> restExcludes = extractNodes(xpath, pom,
                "//profile[id='test-non-services']//plugin[artifactId='maven-surefire-plugin']//exclude");

        assertThat(serviceIncludes)
                .describedAs("test-services profile must define at least one <include> pattern in pom.xml")
                .isNotEmpty();

        assertThat(restExcludes)
                .describedAs("test-non-services profile must define at least one <exclude> pattern in pom.xml")
                .isNotEmpty()
                .describedAs("""
                        test-non-services <excludes> and test-services <includes> in pom.xml must be identical sets.
                        A pattern in one but not the other causes tests to run twice or not at all.
                        Update both profiles together whenever the split pattern changes.""")
                .containsExactlyInAnyOrderElementsOf(serviceIncludes);
    }

    @Test
    void everyRunnableTestInServicePackageMustMatchSplitPattern() throws IOException {
        List<String> splitSuffixes = List.of("Test.java", "Tests.java", "ITest.java");
        Path serviceDir = Path.of("src/test/java/com/czertainly/core/service");

        List<String> violations;
        try (Stream<Path> stream = Files.walk(serviceDir)) {
            violations = stream
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> splitSuffixes.stream().noneMatch(suffix -> p.getFileName().toString().endsWith(suffix)))
                    .filter(p -> !isAbstractClass(p))
                    .filter(CiTestSplitTest::containsTestAnnotation)
                    .map(p -> serviceDir.relativize(p).toString())
                    .sorted()
                    .toList();
        }

        assertThat(violations)
                .describedAs("""
                        Test classes in service/ whose names don't end with Test, Tests, or ITest.
                        They are not picked up by the test-services Maven profile and run in test-non-services instead.
                        Either rename them to match the pattern, or update both <includes> in test-services
                        and <excludes> in test-non-services in pom.xml to cover the new suffix.""")
                .isEmpty();
    }

    private static boolean containsTestAnnotation(Path file) {
        try {
            String source = Files.readString(file);
            return source.contains("@Test") || source.contains("@ParameterizedTest") || source.contains("@RepeatedTest");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static boolean isAbstractClass(Path file) {
        try {
            return Files.readString(file).contains("abstract class");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static List<String> extractNodes(XPath xpath, Document doc, String expression) throws Exception {
        NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);
        List<String> result = new ArrayList<>(nodes.getLength());
        for (int i = 0; i < nodes.getLength(); i++) {
            result.add(nodes.item(i).getTextContent().trim());
        }
        return result;
    }
}
