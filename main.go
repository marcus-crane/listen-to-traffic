package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	Type          string `json:"type"`
	DomainName    string `json:"domain_name"`
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

		if err := handle.SetBPFFilter("udp or tcp"); err != nil {
			panic(err)
		}

		packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

		for packet := range packets {
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer != nil {
				dnsPacket, ok := dnsLayer.(*layers.DNS)
				if !ok {
					fmt.Println("Failed to parse DNS packet")
					continue
				}

				for _, q := range dnsPacket.Questions {
					evt := Event{
						NS:        "Main",
						PageTitle: string(q.Name),
						URL:       "https://en.wikipedia.org/w/index.php?diff=1189341884&oldid=1187982211",
						User:      "Blah",

						DomainName:    string(q.Name),
						Type:          q.Type.String(),
						PacketLength:  packet.Metadata().Length,
						SourceIP:      packet.NetworkLayer().NetworkFlow().Src().String(),
						DestinationIP: packet.NetworkLayer().NetworkFlow().Dst().String(),
					}
					byt, err := json.Marshal(evt)
					if err != nil {
						continue
					}
					Server.Publish("messages", &sse.Event{
						Data: byt,
					})
				}

				for _, a := range dnsPacket.Answers {
					spew.Dump(a) 
					evt := Event{
						NS:        "Main",
						PageTitle: a.IP.String(),
						URL:       "https://en.wikipedia.org/w/index.php?diff=1189341884&oldid=1187982211",
						User:      "Blah",

						DomainName:    string(a.IP.String()),
						Type:          a.Type.String(),
						PacketLength:  packet.Metadata().Length,
						SourceIP:      packet.NetworkLayer().NetworkFlow().Src().String(),
						DestinationIP: packet.NetworkLayer().NetworkFlow().Dst().String(),
					}
					byt, err := json.Marshal(evt)
					if err != nil {
						continue
					}
					Server.Publish("messages", &sse.Event{
						Data: byt,
					})
				}
			}
		}
	}()

	http.ListenAndServe(":9999", handler)
}
