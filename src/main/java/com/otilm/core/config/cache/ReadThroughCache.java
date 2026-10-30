package com.otilm.core.config.cache;

import com.github.benmanes.caffeine.cache.AsyncCache;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.function.Predicate;
import org.springframework.cache.CacheManager;
import org.springframework.cache.support.AbstractValueAdaptingCache;

/**
 * A cache that stores each load while it runs, so an eviction during the load also drops its result.
 *
 * <p>
 * Spring's own Caffeine cache adds an entry only once its load finishes, so a clear during the load misses it. The
 * entries here live in a Caffeine {@code AsyncCache}, and each load runs on its caller's thread, where the security
 * context, transaction and log context it reads are bound.
 */
public class ReadThroughCache extends AbstractValueAdaptingCache {

    private static final String LOADED_ONLY = "Entries of a read-through cache are only loaded through getOrLoad";
    private static final String OWN_KEY_READ = "A loader cannot read the key it is loading";

    private final String name;
    private final AsyncCache<Object, Object> cache;

    public ReadThroughCache(String name, AsyncCache<Object, Object> cache) {
        super(true);
        this.name = name;
        this.cache = cache;
    }

    /** The named cache of a manager whose caches are all read-through. */
    public static ReadThroughCache from(CacheManager cacheManager, String name) {
        return (ReadThroughCache) Objects.requireNonNull(cacheManager.getCache(name), name);
    }

    /**
     * The value stored under the key; callers that miss it at the same time share one load. A caller whose shared load
     * failed leads the next one, or loads uncached while another caller leads it.
     */
    public <T, E extends Exception> T getOrLoad(Object key, Loader<T, E> loader) throws E {
        return getOrLoad(key, loader, loaded -> true);
    }

    /** The cache keeps the loaded value only when it passes {@code keep}. */
    public <T, E extends Exception> T getOrLoad(Object key, Loader<T, E> loader, Predicate<? super T> keep) throws E {
        return getOrLoad(key, loader, keep, cacheable -> {
        });
    }

    /** {@code beforeKeeping} runs on each value passing {@code keep}, before another caller can read it. */
    public <T, E extends Exception> T getOrLoad(Object key, Loader<T, E> loader, Predicate<? super T> keep,
            Consumer<? super T> beforeKeeping) throws E {
        CompletableFuture<Object> mine = new Load();
        boolean completedNormally = false;
        try {
            T value = loadOrJoin(key, mine, loader, keep, beforeKeeping);
            completedNormally = true;
            return value;
        } finally {
            if (!completedNormally) {
                abandon(key, mine);
            }
        }
    }

    private <T, E extends Exception> T loadOrJoin(Object key, CompletableFuture<Object> mine, Loader<T, E> loader,
            Predicate<? super T> keep, Consumer<? super T> beforeKeeping) throws E {
        CompletableFuture<Object> current = claim(key, mine);
        if (current != mine && !awaitSuccess(current)) {
            current = claim(key, mine);
            if (current != mine && current.state() != Future.State.SUCCESS) {
                return loader.load();
            }
        }
        if (current == mine) {
            return lead(key, mine, loader, keep, beforeKeeping);
        }
        return userValue(current.resultNow());
    }

    /** The load under the key, which is {@code mine} when no other caller leads one. */
    private CompletableFuture<Object> claim(Object key, CompletableFuture<Object> mine) {
        return cache.get(key, (k, executor) -> mine);
    }

    /** Waits for a load another caller leads. A failed load has already freed its key. */
    private static boolean awaitSuccess(CompletableFuture<Object> load) {
        if (load instanceof Load running && running.isLedByCurrentThread()) {
            throw new IllegalStateException(OWN_KEY_READ);
        }
        return load.handle((value, failure) -> failure == null).join();
    }

    /**
     * Drops every running load, under every key. An eviction through an index calls this first, for the loads yet to
     * write their index entry.
     */
    public void evictInFlight() {
        cache.asMap().forEach((key, future) -> {
            if (future.state() == Future.State.RUNNING) {
                drop(key, future);
            }
        });
    }

    private void drop(Object key, CompletableFuture<Object> load) {
        cache.asMap().remove(key, load);
    }

    private <T, E extends Exception> T lead(Object key, CompletableFuture<Object> mine, Loader<T, E> loader,
            Predicate<? super T> keep, Consumer<? super T> beforeKeeping) throws E {
        T value = loader.load();
        if (keep.test(value)) {
            beforeKeeping.accept(value);
            mine.complete(toStoreValue(value));
        } else {
            completeUncached(key, mine, value);
        }
        return value;
    }

    /**
     * Frees the key for the waiting callers' retry, then cancels the load. Caffeine logs a warning for every failed
     * load but a cancelled or timed-out one.
     */
    private void abandon(Object key, CompletableFuture<Object> load) {
        drop(key, load);
        load.cancel(false);
    }

    /** Drops the load before completing it, so only the callers already waiting receive the rejected value. */
    private void completeUncached(Object key, CompletableFuture<Object> load, Object value) {
        drop(key, load);
        load.complete(toStoreValue(value));
    }

    @SuppressWarnings("unchecked")
    private <T> T userValue(Object storeValue) {
        return (T) fromStoreValue(storeValue);
    }

    @Override
    public <T> T get(Object key, Callable<T> valueLoader) {
        try {
            return getOrLoad(key, valueLoader::call);
        } catch (Exception e) {
            throw new ValueRetrievalException(key, valueLoader, e);
        }
    }

    @Override
    protected Object lookup(Object key) {
        CompletableFuture<Object> future = cache.getIfPresent(key);
        return future != null && future.state() == Future.State.SUCCESS ? future.resultNow() : null;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public AsyncCache<Object, Object> getNativeCache() {
        return cache;
    }

    /** A write could publish a value an eviction has already dropped. */
    @Override
    public void put(Object key, Object value) {
        throw new UnsupportedOperationException(LOADED_ONLY);
    }

    @Override
    public ValueWrapper putIfAbsent(Object key, Object value) {
        throw new UnsupportedOperationException(LOADED_ONLY);
    }

    @Override
    public void evict(Object key) {
        cache.synchronous().invalidate(key);
    }

    @Override
    public boolean evictIfPresent(Object key) {
        return cache.asMap().remove(key) != null;
    }

    @Override
    public void clear() {
        cache.synchronous().invalidateAll();
    }

    @Override
    public boolean invalidate() {
        boolean notEmpty = !cache.asMap().isEmpty();
        clear();
        return notEmpty;
    }

    /** A load that knows its leader's thread, so a loader reading its own key fails at once. */
    private static final class Load extends CompletableFuture<Object> {

        private final long leaderThreadId = Thread.currentThread().threadId();

        boolean isLedByCurrentThread() {
            return !isDone() && leaderThreadId == Thread.currentThread().threadId();
        }
    }

    /** A load run on its caller's thread, outside any lock. It may throw a checked exception of its own. */
    @FunctionalInterface
    public interface Loader<T, E extends Exception> {
        T load() throws E;
    }
}
