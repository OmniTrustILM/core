package com.czertainly.core.provisioning;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

/**
 * Response DTO containing pre-rendered installation instructions.
 *
 * @param command the command specification containing the rendered shell command
 */
public record InstallationInstructionsDTO(
        @NotNull @Valid Command command
) {
    /**
     * Command specification with the shell command string.
     *
     * @param shell the fully rendered shell command ready for execution
     */
    public record Command(
            @NotNull String shell
    ) {}
}
