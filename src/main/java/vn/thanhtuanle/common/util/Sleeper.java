package vn.thanhtuanle.common.util;

import org.springframework.stereotype.Component;

import java.time.Duration;

/** Blocks the calling thread for a while. A bean so tests can observe a delay instead of waiting it out. */
@Component
public class Sleeper {

    /** Returns at once for zero. An interrupt ends the sleep early and leaves the thread's interrupt flag set. */
    public void sleep(Duration duration) {
        if (duration == null || duration.isZero() || duration.isNegative()) {
            return;
        }
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
