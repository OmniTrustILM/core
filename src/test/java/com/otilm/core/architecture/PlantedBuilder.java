package com.otilm.core.architecture;

/** The compliant neighbour of the builders planted for {@link TestStyleArchSelfTest}. */
public final class PlantedBuilder {

    private String name = "planted";

    public static PlantedBuilder aPlanted() {
        return new PlantedBuilder();
    }

    public PlantedBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public String build() {
        return name;
    }
}
