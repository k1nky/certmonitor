package monitor

import (
	"log"
	"time"

	"github.com/miekg/dns"
)

func (m Monitor) FetchDNS() {
	delay := time.Duration(m.Ctx.RetransferDelay) * time.Second
	go func() {
		ticker := time.NewTicker(delay)

		for {
			select {
			case <-ticker.C:
				for _, zone := range m.Ctx.Zones {
					records := getZone(zone)
					for _, v := range records {
						hdr := v.Header()
						name := hdr.Name[:len(hdr.Name)-1]
						state := DBStateRow{
							Host: name,
							SNI:  name,
						}
						if hdr.Rrtype == dns.TypeA {
							state.Host = state.Host + ":443"
						} else if hdr.Rrtype == dns.TypeMX {
							mx := v.(*dns.MX)
							name = mx.Mx[:len(mx.Mx)-1]
							state.Host = name + ":465"
							state.SNI = name
						} else {
							continue
						}
						m.DB.InsertState(state)
					}
				}
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
		log.Println(err)
		return
	}

	for m := range ch {
		if m.Error != nil {
			log.Println(m.Error)
			continue
		}
		records = append(records, m.RR...)
	}
	return
}

/*
func TestDNS2() {
	master := "192.168.222.4:53"
	d := net.Dialer{}
	con, _ := d.Dial("udp", master)
	defer con.Close()
	dnscon := &dns.Conn{
		Conn: con,
	}
	defer dnscon.Close()
	transfer := &dns.Transfer{Conn: dnscon}

	var msg *dns.Msg

	ch, err := transfer.In(msg, master)
	if err != nil {
		fmt.Println(err)
	}
	answer := <-ch
	fmt.Println(answer.RR)
}
*/
