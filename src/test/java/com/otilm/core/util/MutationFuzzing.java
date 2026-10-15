package com.otilm.core.util;

import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.function.Predicate;
import org.junit.jupiter.api.function.ThrowingConsumer;

import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Mutation fuzzing of a reader of untrusted input: mutants of a valid input must each end in a defined outcome, in
 * bounded time.
 *
 * <p>
 * The seed fixes the mutations made of a given input; an input generated afresh on each run gets other mutants under
 * the same seed. A failure therefore names the seed and the mutant's index and shows the mutant itself in Base64, which
 * reproduces it.
 * </p>
 */
public final class MutationFuzzing {

    private static final Duration PER_MUTANT = Duration.ofSeconds(5);

    /** The most bytes one mutation flips, deletes or duplicates. */
    private static final int MAXIMUM_RUN = 8;

    private MutationFuzzing() {
    }

    /**
     * Reads mutants of the valid input, each made by flipping, deleting, duplicating or truncating bytes the seeded
     * random source chooses, and asserts that every read returns, or throws what the reader defines, within five
     * seconds.
     *
     * @param valid the input the mutants are made from, at least one byte long
     * @param seed the seed of the random source that chooses the mutations
     * @param mutants how many mutants to read
     * @param read reads one mutant
     * @param defined whether a throwable is an outcome the reader defines, such as its refusal
     */
    public static void assertOnlyDefinedOutcomes(byte[] valid, long seed, int mutants, ThrowingConsumer<byte[]> read,
            Predicate<Throwable> defined) {
        Random random = new Random(seed);
        for (int index = 0; index < mutants; index++) {
            byte[] mutant = mutant(valid, random);
            String name = "Mutant %d of seed %d (%s)"
                    .formatted(index, seed, Base64.getEncoder().encodeToString(mutant));
            Throwable outcome = assertTimeoutPreemptively(PER_MUTANT, () -> catchThrowable(() -> read.accept(mutant)),
                    () -> name + " was not read within " + PER_MUTANT.toSeconds() + " seconds");
            if (outcome != null && !defined.test(outcome)) {
                fail(name + " ended in an outcome the reader does not define", outcome);
            }
        }
    }

    private static byte[] mutant(byte[] valid, Random random) {
        int position = random.nextInt(valid.length);
        int run = 1 + random.nextInt(Math.min(MAXIMUM_RUN, valid.length - position));
        return switch (random.nextInt(4)) {
            case 0 -> flipped(valid, position, run, random);
            case 1 -> deleted(valid, position, run);
            case 2 -> duplicated(valid, position, run);
            default -> Arrays.copyOf(valid, position);
        };
    }

    /** Each byte of the run with at least one of its bits flipped. */
    private static byte[] flipped(byte[] valid, int position, int run, Random random) {
        byte[] mutant = valid.clone();
        for (int i = position; i < position + run; i++) {
            mutant[i] ^= (byte) (1 + random.nextInt(255));
        }
        return mutant;
    }

    private static byte[] deleted(byte[] valid, int position, int run) {
        byte[] mutant = new byte[valid.length - run];
        System.arraycopy(valid, 0, mutant, 0, position);
        System.arraycopy(valid, position + run, mutant, position, valid.length - position - run);
        return mutant;
    }

    /** The run followed by a copy of itself. */
    private static byte[] duplicated(byte[] valid, int position, int run) {
        byte[] mutant = new byte[valid.length + run];
        System.arraycopy(valid, 0, mutant, 0, position + run);
        System.arraycopy(valid, position, mutant, position + run, valid.length - position);
        return mutant;
    }
}
