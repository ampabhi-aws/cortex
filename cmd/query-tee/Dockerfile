# Pin a supported Alpine base by digest (alpine:3.19).
FROM       alpine:3.19@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
RUN        apk --no-cache upgrade && apk add --no-cache ca-certificates && \
           addgroup -g 10001 -S cortex && adduser -u 10001 -S cortex -G cortex
COPY       query-tee /
USER       10001:10001
EXPOSE     8080
ENTRYPOINT ["/query-tee"]

ARG revision
LABEL org.opencontainers.image.title="query-tee" \
      org.opencontainers.image.source="https://github.com/cortexproject/cortex/tree/master/tools/query-tee" \
      org.opencontainers.image.revision="${revision}"
