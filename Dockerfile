# syntax=docker/dockerfile:1.7
#
# Static Go binary on distroless. GOFIPS140 links Go's native FIPS 140-3 module (v1.0.0 is the
# frozen version submitted for CMVP validation) and turns FIPS mode on by default. No OpenSSL or
# cgo is involved, so the crypto boundary is the Go module plus Cloud KMS HSMs for key wrapping.
#
#   docker build -t strongbox .
#   docker run --rm strongbox fips-check   # exits non-zero unless FIPS mode is active

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
ARG GOFIPS140=v1.0.0
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFIPS140=${GOFIPS140} go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" -o /out/strongbox ./cmd/strongbox \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/strongbox /strongbox
COPY --from=build --chown=65532:65532 /out/data /data
# fips140=on runs in FIPS mode. fips140=only additionally makes non-approved algorithms fail outright;
# the full test suite passes in that mode, so switch to it once verified against your GCP endpoints.
ENV GODEBUG=fips140=on
USER 65532:65532
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/strongbox"]
CMD ["serve"]
