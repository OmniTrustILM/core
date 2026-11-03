package com.otilm.core.architecture;

/** A builder planted for {@link TestStyleArchSelfTest} that is package-private and open to subclassing. */
class PlantedLooseBuilder {

    private String name = "planted";

    String build() {
        return name;
    }
}
