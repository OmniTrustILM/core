package com.otilm.core.architecture;

import org.springframework.boot.test.context.SpringBootTest;

/**
 * A test class planted for {@link TestStyleArchSelfTest} that declares its own {@code @SpringBootTest}. It has a file
 * of its own, as {@link TestClassTaxonomy} counts a test source carrying the annotation as one that loads a context.
 */
@SpringBootTest
abstract class PlantedSpringBootTestCarrier {
}
