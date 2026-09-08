FROM golang:1.24-alpine AS builder

ARG TARGETOS TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o /out/cfst .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl jq
COPY --from=builder /out/cfst /usr/local/bin/cfst
COPY ip.txt /ip.txt
COPY ipv6.txt /ipv6.txt

WORKDIR /data
ENTRYPOINT ["cfst"]
CMD ["-f", "/ip.txt"]