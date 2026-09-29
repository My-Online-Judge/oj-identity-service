package vn.thanhtuanle.common;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The OpenTelemetry Java agent puts the current trace id into the MDC as {@code trace_id}. The
 * log pattern must print it next to the submission id, so a log line can be matched to its trace
 * in Jaeger.
 */
@SpringBootTest
@ActiveProfiles("test")
@ExtendWith(OutputCaptureExtension.class)
class LogCorrelationPatternTest {

    @Test
    void logLinesCarryTheTraceIdAndTheSubmissionId(CapturedOutput output) {
        MDC.put("trace_id", "4bf92f3577b34da6a3ce929d0e0e4736");
        MDC.put("submissionId", "sub-1");
        try {
            LoggerFactory.getLogger(LogCorrelationPatternTest.class).info("correlation probe");
        } finally {
            MDC.remove("trace_id");
            MDC.remove("submissionId");
        }
        assertThat(output).contains("[4bf92f3577b34da6a3ce929d0e0e4736] [sub-1] ");
    }
}
