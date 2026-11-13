FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
LABEL maintainer="The OpenTelemetry Authors"
WORKDIR /
COPY bin/obi /obi
COPY LICENSE NOTICE ./
COPY NOTICES ./NOTICES
COPY --from=certs /etc/ssl/certs /etc/ssl/certs
ENTRYPOINT ["/obi"]
