package monitor

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
)

func (mon Monitor) discoveryZones() {
	for _, zone := range mon.Cfg.Zones {
		records := getZone(zone)
		for _, v := range records {
			hdr := v.Header()
			if hdr.Rrtype == dns.TypeA {
				name := hdr.Name[:len(hdr.Name)-1]
				mon.DB.InsertState(DBStateRow{
					Host: name + ":443",
					SNI:  name,
					Type: DiscoveryState,
				})
			} else if !zone.OmitMx && hdr.Rrtype == dns.TypeMX {
				mx := v.(*dns.MX)
				name := mx.Mx[:len(mx.Mx)-1]
				mon.DB.InsertState(DBStateRow{
					Host: fmt.Sprintf("%s:%d", name, zone.PortMX),
					SNI:  name,
					Type: DiscoveryState,
				})
			}
		}
	}
}

// FetchDNS periodically requests and receives monitoring zones
func (mon Monitor) FetchDNS(ctx context.Context) {
	delay := time.Duration(mon.Cfg.RetransferDelay) * time.Second
	ticker := time.NewTicker(delay)
	log.Println("Start discovery DNS zones")
	go func() {
		for {
			mon.discoveryZones()
			select {
			case <-ctx.Done():
				ticker.Stop()
				log.Println("Stop discovery DNS zones")
				return
			case <-ticker.C:
			}
		}
	}()
}

func getZone(zone ZoneConfig) (records []dns.RR) {
	var (
		tr  *dns.Transfer
		msg *dns.Msg
	)
	tr = new(dns.Transfer)
	msg = new(dns.Msg)

	msg.SetAxfr(zone.Name)
	ch, err := tr.In(msg, zone.Master)
	if err != nil {
		log.Printf("Transfer zone %s from %s is failed: %s",
			zone.Name, zone.Master, err)
		return
	}

	for m := range ch {
		if m.Error != nil {
			log.Println(m.Error)
			continue
		}
		records = append(records, m.RR...)
	}
	log.Printf("Transfer zone %s from %s is successfully\n", zone.Name, zone.Master)
	return
}
