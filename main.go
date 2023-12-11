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
	Action        string   `json:"action"`
	ChangeSize    int      `json:"change_size"`
	Flags         string   `json:"flags"`
	Hashtags      []string `json:"hashtags"`
	IsAnon        bool     `json:"is_anon"`
	IsBot         bool     `json:"is_bot"`
	IsMinor       bool     `json:"is_minor"`
	IsNew         bool     `json:"is_new"`
	IsUnpatrolled bool     `json:"is_unpatrolled"`
	Mentions      []string `json:"mentions"`
	NS            string   `json:"ns"`
	PageTitle     string   `json:"page_title"`
	ParentRevId   string   `json:"parent_rev_id"`
	ParsedSummary string   `json:"parsed_summary"`
	RevId         string   `json:"rev_id"`
	Section       string   `json:"section"`
	Summary       string   `json:"summary"`
	URL           string   `json:"url"`
	User          string   `json:"user"`
}

func main() {
	server := sse.New()
	server.AutoReplay = false
	server.CreateStream("messages")
	Server = server

	mux := http.NewServeMux()
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
				Action:      "edit",
				ChangeSize:  pkt.Metadata().Length,
				Flags:       "M",
				IsMinor:     true,
				NS:          "Main",
				PageTitle:   pkt.NetworkLayer().NetworkFlow().Dst().String(),
				ParentRevId: "1189341884",
				RevId:       "1187982211",
				Section:     "External links",
				Summary:     "/* External links */",
				URL:         "https://en.wikipedia.org/w/index.php?diff=1189341884&oldid=1187982211",
				User:        "DepressedPer",
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
