# Optimize stage
FROM eclipse-temurin:21-jdk-alpine AS optimize

COPY data/target/*.jar /app/app.jar

WORKDIR /app

# List jar modules
RUN jar xf app.jar
RUN jdeps \
  --ignore-missing-deps \
  --print-module-deps \
  --multi-release 21 \
  --recursive \
  --class-path 'BOOT-INF/lib/*' \
  app.jar > modules.txt

# Create a custom Java runtime
# - 'jdk.crypto.ec' is required for elliptic-curve cryptography support.
# - 'jdk.naming.dns' is required for DNS lookups for ACME challenges.
# These modules can be overridden or extended using the ADDITIONAL_MODULES environment variable.
ENV ADDITIONAL_MODULES=jdk.crypto.ec,jdk.naming.dns
RUN $JAVA_HOME/bin/jlink \
  --add-modules $(cat modules.txt),${ADDITIONAL_MODULES} \
  --strip-debug \
  --no-man-pages \
  --no-header-files \
  --compress=2 \
  --output /javaruntime

# Package stage
FROM alpine:3.23

ENV JAVA_HOME=/opt/jre
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# copy optimized JRE
COPY --from=optimize /javaruntime $JAVA_HOME

LABEL org.opencontainers.image.authors="CZERTAINLY <support@czertainly.com>"

# add non root user czertainly
RUN addgroup --system --gid 10001 czertainly && adduser --system --home /opt/czertainly --uid 10001 --ingroup czertainly czertainly

# apk upgrade should be removed once CVEs will be fixed in eclipse-temurin:21-jdk-alpine-3.23
RUN apk update && \
  apk --no-cache upgrade && \
  apk add --no-cache curl

COPY data/docker /
COPY data/target/*.jar /opt/czertainly/app.jar

WORKDIR /opt/czertainly

# default environment variables
ENV DB_SCHEMA=core
ENV PORT=8080
ENV HEADER_NAME=ssl-client-cert
ENV SCHEDULED_TASKS_ENABLED=true
ENV BROKER_HOST=
ENV BROKER_PORT=5672
ENV BROKER_VIRTUAL_HOST=czertainly
ENV PROVISIONING_API_URL=http://localhost:8080
ENV PROVISIONING_API_KEY=

USER 10001

ENTRYPOINT ["/opt/czertainly/entry.sh"]
