package monitor

import (
	"log"
	"time"

	"github.com/miekg/dns"
)

// FetchDNS periodically requests and receives monitoring zones
func (m Monitor) FetchDNS() {
	delay := time.Duration(m.Ctx.RetransferDelay) * time.Second
	go func() {
		for {
			for _, zone := range m.Ctx.Zones {
				records := getZone(zone)
				for _, v := range records {
					hdr := v.Header()
					if hdr.Rrtype == dns.TypeA {
						name := hdr.Name[:len(hdr.Name)-1]
						m.DB.InsertState(DBStateRow{
							Host: name + ":443",
							SNI:  name,
							Type: DiscoveryState,
						})
					} else if hdr.Rrtype == dns.TypeMX {
						mx := v.(*dns.MX)
						name := mx.Mx[:len(mx.Mx)-1]
						m.DB.InsertState(DBStateRow{
							Host: name + ":465",
							SNI:  name,
							Type: DiscoveryState,
						})
					}
				}
			}
			time.Sleep(delay)
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
