# Build stage. Debian-based, not Alpine: oj-common generates its gRPC stubs with protoc, a glibc binary.
FROM maven:3.9-eclipse-temurin-17 AS builder
# oj-common is a sibling repo that is not published yet: compile it into this build's local Maven
# repository first. Compose passes it as the named build context "oj-common" (additional_contexts).
COPY --from=oj-common . /oj-common
RUN mvn -B -q -f /oj-common/pom.xml install -DskipTests
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package -DskipTests
# Run stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
# curl: the compose healthcheck calls the actuator over mutual TLS, presenting this service's certificate
# (busybox wget cannot send a client certificate).
RUN apk add --no-cache curl
# OpenTelemetry Java agent, pinned and checksum-verified. The deployment ENABLES it with
# JAVA_TOOL_OPTIONS=-javaagent:/otel/opentelemetry-javaagent.jar; without that the image runs untraced.
ARG OTEL_AGENT_VERSION=2.31.1
ARG OTEL_AGENT_SHA256=bbf83c151b6400709e2f225bdd07a04f839d9d13b8b93464241333fd25d3e3ba
RUN mkdir /otel \
    && wget -q -O /otel/opentelemetry-javaagent.jar \
       "https://repo1.maven.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/${OTEL_AGENT_VERSION}/opentelemetry-javaagent-${OTEL_AGENT_VERSION}.jar" \
    && echo "${OTEL_AGENT_SHA256}  /otel/opentelemetry-javaagent.jar" | sha256sum -c -
COPY --from=builder /app/target/identity-service.jar app.jar
# 8000 = API (oj-net only), 8081 = actuator (health, prometheus)
EXPOSE 8000 8081
# Non-root (sp12): the app and /otel are root-owned and world-readable; it writes only /tmp.
RUN addgroup -S -g 10001 oj && adduser -S -D -H -u 10001 -G oj oj
USER 10001:10001
ENTRYPOINT ["java", "-jar", "app.jar"]