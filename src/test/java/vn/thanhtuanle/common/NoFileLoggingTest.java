package vn.thanhtuanle.common;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.core.FileAppender;
import ch.qos.logback.core.Appender;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.test.context.ActiveProfiles;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Containers log to stdout (docker rotates it); a file in the image's writable layer would grow unbounded. */
@SpringBootTest
@ActiveProfiles("test")
class NoFileLoggingTest {

    @Test
    void rootLoggerHasNoFileAppender() {
        Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        List<Appender<?>> appenders = new ArrayList<>();
        for (Iterator<?> it = root.iteratorForAppenders(); it.hasNext(); ) {
            appenders.add((Appender<?>) it.next());
        }
        assertThat(appenders).isNotEmpty().noneMatch(a -> a instanceof FileAppender);
    }

    @Test
    void noProfileSetsALogFile() throws Exception {
        Resource[] files = new PathMatchingResourcePatternResolver().getResources("classpath*:application*.yml");
        assertThat(files).isNotEmpty();
        for (Resource file : files) {
            try (InputStream in = file.getInputStream()) {
                for (Object doc : new Yaml().loadAll(in)) {
                    Map<String, Object> flat = new java.util.HashMap<>();
                    flatten("", doc, flat);
                    assertThat(flat).as(file.getFilename())
                            .doesNotContainKeys("logging.file.name", "logging.file.path");
                }
            }
        }
    }

    private static void flatten(String prefix, Object node, Map<String, Object> out) {
        if (node instanceof Map<?, ?> map) {
            map.forEach((k, v) -> flatten(prefix.isEmpty() ? String.valueOf(k) : prefix + "." + k, v, out));
        } else if (node != null) {
            out.put(prefix, node);
        }
    }
}
