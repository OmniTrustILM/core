#!/bin/sh

otilmHome="/opt/otilm"
source ${otilmHome}/static-functions

# A JSON console format has to start with JSON, so it gets no plain-text launch line
case "$(echo "${PLATFORM_LOG_FORMAT}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in
    ecs|logstash) ;;
    *) log "INFO" "Launching the Core" ;;
esac
exec java $JAVA_OPTS -jar ./app.jar
