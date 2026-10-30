package com.otilm.core.config.cache;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.core.util.cache.Caller;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.logging.Filter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.cache.Cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ReadThroughCacheTest {

    private static final String KEY = "key";
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final IllegalStateException CALLBACK_FAILURE = new IllegalStateException("callback failed");

    /** Caffeine reports a failed asynchronous load through the platform logger of this name. */
    private static final String CAFFEINE_ASYNC_LOGGER = "com.github.benmanes.caffeine.cache.LocalAsyncCache";

    private ReadThroughCache cache;
    private AtomicInteger loads;

    @BeforeEach
    void setUp() {
        cache = new ReadThroughCache("test", Caffeine.newBuilder().maximumSize(100).buildAsync());
        loads = new AtomicInteger();
    }

    private String load() {
        return "value-" + loads.incrementAndGet();
    }

    @Test
    void aSecondCallIsServedFromTheCache() {
        String first = cache.getOrLoad(KEY, this::load);
        String second = cache.getOrLoad(KEY, this::load);

        assertThat(second).isEqualTo(first);
        assertThat(loads).hasValue(1);
    }

    @Test
    void aCallerArrivingDuringALoadSharesIt() throws Exception {
        // given
        GatedLoader gate = new GatedLoader();
        Caller<String> leader = Caller.start(() -> cache.getOrLoad(KEY, gate::load));
        gate.awaitEntered();
        Caller<String> follower = Caller.start(() -> cache.getOrLoad(KEY, this::load));
        follower.awaitParked();

        // when
        gate.open();

        // then
        assertThat(leader.value()).isEqualTo("value-1");
        assertThat(follower.value()).isEqualTo("value-1");
        assertThat(loads).hasValue(1);
    }

    @Test
    void aFailedLoadFailsOnlyTheCallerThatRanIt() throws Exception {
        // given
        GatedLoader gate = new GatedLoader();
        Caller<String> leader = Caller.start(() -> cache.getOrLoad(KEY, gate::load));
        gate.awaitEntered();
        Caller<String> follower = Caller.start(() -> cache.getOrLoad(KEY, this::load));
        follower.awaitParked();
        IllegalStateException failure = new IllegalStateException("backend down");

        // when
        gate.fail(failure);

        // then
        assertThat(leader.result())
                .failsWithin(TIMEOUT)
                .withThrowableOfType(ExecutionException.class)
                .havingCause()
                .isSameAs(failure);
        assertThat(follower.value()).isEqualTo("value-1");
        assertThat(loads).hasValue(1);
    }

    @Test
    void theCallersWaitingOnAFailedLoadLoadAgainAtOnce() throws Exception {
        // given
        GatedLoader failing = ledLoad();
        GatedLoader retries = new GatedLoader(2);
        parkedCallers(retries, cacheable -> {
        });

        // when
        failing.fail(new IllegalStateException("backend down"));

        // then — neither caller waits on the other's load
        retries.awaitEntered();
    }

    @Test
    void aCallerBackFromAFailedLoadRefillsTheCache() throws Exception {
        // given
        GatedLoader failing = ledLoad();
        GatedLoader retries = new GatedLoader(2);
        List<Caller<String>> callers = parkedCallers(retries, cacheable -> {
        });
        failing.fail(new IllegalStateException("backend down"));
        retries.awaitEntered();

        // when
        retries.open();

        // then
        List<String> loaded = List.of(callers.get(0).value(), callers.get(1).value());
        assertThat(cache.getOrLoad(KEY, this::load)).isIn(loaded);
        assertThat(loads).hasValue(2);
    }

    @Test
    void aCallerLoadingUncachedSkipsBeforeKeeping() throws Exception {
        // given
        GatedLoader failing = ledLoad();
        GatedLoader retries = new GatedLoader(2);
        List<String> prepared = new CopyOnWriteArrayList<>();
        List<Caller<String>> callers = parkedCallers(retries, prepared::add);
        failing.fail(new IllegalStateException("backend down"));
        retries.awaitEntered();

        // when
        retries.open();

        // then
        callers.get(0).value();
        callers.get(1).value();
        assertThat(prepared).containsExactly(cache.getOrLoad(KEY, this::load));
    }

    @Test
    void aFailedLoadStoresNothing() {
        IllegalStateException failure = new IllegalStateException("backend down");

        assertThatThrownBy(() -> cache.getOrLoad(KEY, () -> {
            throw failure;
        })).isSameAs(failure);

        assertThat(cache.get(KEY)).isNull();
        assertThat(cache.getOrLoad(KEY, this::load)).isEqualTo("value-1");
    }

    @Test
    void aFailedLoadLogsNoWarning() {
        // given
        Logger caffeineLogger = Logger.getLogger(CAFFEINE_ASYNC_LOGGER);
        Level previousLevel = caffeineLogger.getLevel();
        Filter previousFilter = caffeineLogger.getFilter();
        List<LogRecord> recorded = new CopyOnWriteArrayList<>();
        caffeineLogger.setLevel(Level.ALL);
        caffeineLogger.setFilter(recorded::add);
        IllegalStateException failure = new IllegalStateException("backend down");

        try {
            // when
            assertThatThrownBy(() -> cache.getOrLoad(KEY, () -> {
                throw failure;
            })).isSameAs(failure);
        } finally {
            caffeineLogger.setFilter(previousFilter);
            caffeineLogger.setLevel(previousLevel);
        }

        // then
        assertThat(recorded).isEmpty();
    }

    @Test
    void aValueFailingKeepIsReturnedUncached() {
        String first = cache.getOrLoad(KEY, this::load, loaded -> false);
        String second = cache.getOrLoad(KEY, this::load, loaded -> false);

        assertThat(first).isEqualTo("value-1");
        assertThat(second).isEqualTo("value-2");
    }

    @Test
    void aValueFailingKeepReachesTheWaitingCaller() throws Exception {
        // given
        GatedLoader gate = new GatedLoader();
        Caller<String> leader = Caller.start(() -> cache.getOrLoad(KEY, gate::load, loaded -> false));
        gate.awaitEntered();
        Caller<String> follower = Caller.start(() -> cache.getOrLoad(KEY, this::load));
        follower.awaitParked();

        // when
        gate.open();

        // then
        assertThat(leader.value()).isEqualTo("value-1");
        assertThat(follower.value()).isEqualTo("value-1");
        assertThat(cache.getOrLoad(KEY, this::load)).isEqualTo("value-2");
    }

    @Test
    void beforeKeepingRunsOnlyOnTheValuesPassingKeep() {
        List<String> prepared = new ArrayList<>();

        cache.getOrLoad("rejected", this::load, loaded -> false, prepared::add);
        cache.getOrLoad("kept", this::load, loaded -> true, prepared::add);

        assertThat(prepared).containsExactly("value-2");
    }

    @Test
    void beforeKeepingRunsBeforeAnotherCallerCanReadTheValue() {
        List<Cache.ValueWrapper> readsWhilePreparing = new ArrayList<>();

        cache.getOrLoad(KEY, this::load, loaded -> true, cacheable -> readsWhilePreparing.add(cache.get(KEY)));

        assertThat(readsWhilePreparing).containsExactly((Cache.ValueWrapper) null);
    }

    static Stream<Arguments> failingCallbacks() {
        Predicate<String> failingKeep = loaded -> {
            throw CALLBACK_FAILURE;
        };
        Consumer<String> failingBeforeKeeping = cacheable -> {
            throw CALLBACK_FAILURE;
        };
        return Stream.of(arguments(named("keep", failingKeep), (Consumer<String>) cacheable -> {
        }), arguments(named("beforeKeeping", (Predicate<String>) loaded -> true), failingBeforeKeeping));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("failingCallbacks")
    void aFailingCallbackFreesTheKeyForTheWaitingCaller(Predicate<String> keep, Consumer<String> beforeKeeping)
            throws Exception {
        // given
        GatedLoader gate = new GatedLoader();
        Caller<String> leader = Caller.start(() -> cache.getOrLoad(KEY, gate::load, keep, beforeKeeping));
        gate.awaitEntered();
        Caller<String> follower = Caller.start(() -> cache.getOrLoad(KEY, this::load));
        follower.awaitParked();

        // when
        gate.open();

        // then
        assertThat(leader.result())
                .failsWithin(TIMEOUT)
                .withThrowableOfType(ExecutionException.class)
                .havingCause()
                .isSameAs(CALLBACK_FAILURE);
        assertThat(follower.value()).isEqualTo("value-2");
        assertThat(cache.getOrLoad(KEY, this::load)).isEqualTo("value-2");
    }

    @Test
    void aNullValueIsStored() {
        Supplier<String> nullLoader = () -> {
            loads.incrementAndGet();
            return null;
        };

        cache.getOrLoad(KEY, nullLoader::get);
        String second = cache.getOrLoad(KEY, nullLoader::get);

        assertThat(second).isNull();
        assertThat(loads).hasValue(1);
        assertThat(cache.get(KEY)).isNotNull().extracting(Cache.ValueWrapper::get).isNull();
    }

    static Stream<Named<Consumer<ReadThroughCache>>> evictions() {
        return Stream
                .of(named("evict", c -> c.evict(KEY)), named("evictIfPresent", c -> c.evictIfPresent(KEY)),
                        named("clear", Cache::clear), named("invalidate", Cache::invalidate),
                        named("evictInFlight", ReadThroughCache::evictInFlight));
    }

    @ParameterizedTest
    @MethodSource("evictions")
    void anEvictionDuringALoadDropsItsResult(Consumer<ReadThroughCache> eviction) throws Exception {
        // given
        GatedLoader gate = new GatedLoader();
        Caller<String> leader = Caller.start(() -> cache.getOrLoad(KEY, gate::load));
        gate.awaitEntered();

        // when
        eviction.accept(cache);
        gate.open();

        // then
        assertThat(leader.value()).isEqualTo("value-1");
        assertThat(cache.getOrLoad(KEY, this::load)).isEqualTo("value-2");
    }

    @Test
    void aCallerWaitingOnAnEvictedLoadReceivesItsResult() throws Exception {
        // given
        GatedLoader gate = new GatedLoader();
        Caller<String> leader = Caller.start(() -> cache.getOrLoad(KEY, gate::load));
        gate.awaitEntered();
        Caller<String> follower = Caller.start(() -> cache.getOrLoad(KEY, this::load));
        follower.awaitParked();

        // when
        cache.evict(KEY);
        gate.open();

        // then
        assertThat(leader.value()).isEqualTo("value-1");
        assertThat(follower.value()).isEqualTo("value-1");
        assertThat(loads).hasValue(1);
    }

    @Test
    void evictInFlightKeepsCompletedEntries() {
        cache.getOrLoad(KEY, this::load);

        cache.evictInFlight();

        assertThat(cache.getOrLoad(KEY, this::load)).isEqualTo("value-1");
    }

    @Test
    void aLookupSeesOnlyACompletedLoad() throws Exception {
        // given
        GatedLoader gate = new GatedLoader();
        Caller<String> leader = Caller.start(() -> cache.getOrLoad(KEY, gate::load));
        gate.awaitEntered();

        // when
        Cache.ValueWrapper duringLoad = cache.get(KEY);
        gate.open();
        leader.value();

        // then
        assertThat(duringLoad).isNull();
        assertThat(cache.get(KEY)).isNotNull().extracting(Cache.ValueWrapper::get).isEqualTo("value-1");
    }

    @Test
    void aValueLoaderFailureIsWrappedForSpring() {
        IllegalStateException failure = new IllegalStateException("backend down");

        assertThatThrownBy(() -> cache.get(KEY, () -> {
            throw failure;
        })).isInstanceOf(Cache.ValueRetrievalException.class).cause().isSameAs(failure);
    }

    @Test
    void aLoaderReadingItsOwnKeyFails() {
        Caller<String> caller = Caller.start(() -> cache.getOrLoad(KEY, () -> cache.getOrLoad(KEY, this::load)));

        assertThat(caller.result())
                .failsWithin(TIMEOUT)
                .withThrowableOfType(ExecutionException.class)
                .havingCause()
                .isInstanceOf(IllegalStateException.class);
        assertThat(cache.getOrLoad(KEY, this::load)).isEqualTo("value-1");
    }

    @Test
    void writesAreRefused() {
        assertThatThrownBy(() -> cache.put(KEY, "value")).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> cache.putIfAbsent(KEY, "value")).isInstanceOf(UnsupportedOperationException.class);
    }

    /** Starts a load another caller leads, held at the returned gate. */
    private GatedLoader ledLoad() throws InterruptedException {
        GatedLoader gate = new GatedLoader();
        Caller.start(() -> cache.getOrLoad(KEY, gate::load));
        gate.awaitEntered();
        return gate;
    }

    /** Starts a caller per load the gate holds, each parked on the running load until that load fails. */
    private List<Caller<String>> parkedCallers(GatedLoader gate, Consumer<String> beforeKeeping) {
        List<Caller<String>> callers = new ArrayList<>();
        for (int i = 0; i < gate.heldLoads; i++) {
            Caller<String> caller = Caller.start(() -> cache.getOrLoad(KEY, gate::load, loaded -> true, beforeKeeping));
            caller.awaitParked();
            callers.add(caller);
        }
        return callers;
    }

    /** A loader that blocks until the test opens it. It then returns a fresh value or throws the given failure. */
    private final class GatedLoader {

        private final int heldLoads;
        private final CountDownLatch entered;
        private final CountDownLatch opened = new CountDownLatch(1);
        private volatile RuntimeException failure;

        GatedLoader() {
            this(1);
        }

        /** A gate that reports itself entered once {@code heldLoads} loads wait at it. */
        GatedLoader(int heldLoads) {
            this.heldLoads = heldLoads;
            this.entered = new CountDownLatch(heldLoads);
        }

        String load() throws InterruptedException {
            entered.countDown();
            assertThat(opened.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS)).as("gate opened").isTrue();
            if (failure != null) {
                throw failure;
            }
            return ReadThroughCacheTest.this.load();
        }

        void awaitEntered() throws InterruptedException {
            assertThat(entered.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS)).as("load started").isTrue();
        }

        void open() {
            opened.countDown();
        }

        void fail(RuntimeException failure) {
            this.failure = failure;
            opened.countDown();
        }
    }
}
