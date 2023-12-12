package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/r3labs/sse/v2"
	"github.com/rs/cors"
)

const (
	defaultSnapLen = 262144
)

var (
	Server *sse.Server
)

type Event struct {
	NS        string `json:"ns"`
	PageTitle string `json:"page_title"`
	URL       string `json:"url"`
	User      string `json:"user"`

	PacketLength  int    `json:"packet_length"`
	SourceIP      string `json:"source_ip"`
	DestinationIP string `json:"destination_ip"`
}

func main() {
	server := sse.New()
	server.AutoReplay = false
	server.CreateStream("messages")
	Server = server

	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("./static"))

	mux.Handle("/", fs)
	mux.HandleFunc("/events", server.ServeHTTP)

	c := cors.New(cors.Options{})

	handler := c.Handler(mux)

	// go func() {
	// 	http.ListenAndServe(":8080", mux)
	// }()

	go func() {
		handle, err := pcap.OpenLive("wlo1", defaultSnapLen, true, pcap.BlockForever)
		if err != nil {
			panic(err)
		}
		defer handle.Close()

		if err := handle.SetBPFFilter("tcp"); err != nil {
			panic(err)
		}

		packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

		for pkt := range packets {
			evt := Event{
				NS:        "Main",
				PageTitle: pkt.NetworkLayer().NetworkFlow().Dst().String(),
				URL:       "https://en.wikipedia.org/w/index.php?diff=1189341884&oldid=1187982211",
				User:      "Blah",

				PacketLength:  pkt.Metadata().Length,
				SourceIP:      pkt.NetworkLayer().NetworkFlow().Src().String(),
				DestinationIP: pkt.NetworkLayer().NetworkFlow().Dst().String(),
			}
			byt, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			Server.Publish("messages", &sse.Event{
				Data: byt,
			})
			fmt.Println("published event")
			// fmt.Printf("Length: %d\n", pkt.Metadata().Length)
			// fmt.Printf("TS: %s\n\n", pkt.Metadata().Timestamp)
		}
	}()

	http.ListenAndServe(":9999", handler)
}
