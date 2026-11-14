FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
LABEL maintainer="The OpenTelemetry Authors"
WORKDIR /
COPY bin/obi /obi
COPY LICENSE NOTICE ./
COPY NOTICES ./NOTICES
COPY --from=certs /etc/ssl/certs /etc/ssl/certs
ENTRYPOINT ["/obi"]
