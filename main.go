package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ysicing/nezha-exporter/collector"
)

var port int

func init() {
	flag.IntVar(&port, "port", 2112, "port to listen on")
}

func main() {
	flag.Parse()
	config := collector.CollectConfig{
		Host:  os.Getenv("NEZHA_HOST"),
		Token: os.Getenv("NEZHA_TOKEN"),
	}
	http.Handle("/metrics", promhttp.Handler())
	log.Println("Listening on :", port)

	go collector.Start(config)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
