FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY examples/dreamcatcher/pack ./examples/dreamcatcher/pack
RUN CGO_ENABLED=0 GOFIPS140=v1.0.0 go build -trimpath -o /out/strongbox ./cmd/strongbox && CGO_ENABLED=0 go build -trimpath -o /out/pack ./examples/dreamcatcher/pack
FROM node:22-bookworm-slim
COPY --from=build /out/ /usr/local/bin/
WORKDIR /demo
COPY examples/dreamcatcher examples/dreamcatcher
RUN mkdir -p /state && chown node:node /state
USER node
ENV SB_BIN=/usr/local/bin/strongbox DC_PACK_BIN=/usr/local/bin/pack DC_LAB_STATE=/state DC_LAB_CONTAINER=1 GODEBUG=fips140=only
CMD ["node","examples/dreamcatcher/lab/start.mjs"]
