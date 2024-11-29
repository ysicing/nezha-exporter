FROM ysicing/god as builder

WORKDIR /go/src

COPY . .

RUN go build -o nezha-exporter main.go

FROM ysicing/debian

LABEL maintainer="ysicing <i@ysicing.me>"

COPY --from=builder /go/src/nezha-exporter /app/nezha-exporter

ENTRYPOINT ["/app/nezha-exporter"]
