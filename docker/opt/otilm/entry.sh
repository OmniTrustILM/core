#!/bin/sh

otilmHome="/opt/otilm"
source ${otilmHome}/static-functions

log "INFO" "Launching the Core"
exec java $JAVA_OPTS -jar ./app.jar
