package vn.thanhtuanle.common.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class SleeperTest {

    private final Sleeper sleeper = new Sleeper();

    @AfterEach
    void clearInterruptFlag() {
        Thread.interrupted();
    }

    @Test
    void zeroReturnsAtOnce() {
        long start = System.nanoTime();

        sleeper.sleep(Duration.ZERO);

        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(50));
    }

    @Test
    void anInterruptedSleepReturnsWithTheInterruptFlagRestored() {
        Thread.currentThread().interrupt();
        long start = System.nanoTime();

        sleeper.sleep(Duration.ofSeconds(8));

        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(1));
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
    }
}
