package fakedns

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/shadowsocks/go-shadowsocks2/internal/android"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/smallnest/iprange"
)

const (
	dnsTimeout = 9 * time.Second
)

var (
	directLookupId uint32

	logf = log.Printf

	bindAddr string

	chinaDNS []string

	probeDNS      []string
	probeDNSMutex = &sync.RWMutex{}

	mapping      = make(map[string]string)
	mappingMutex = &sync.RWMutex{}

	alwaysDirect      = make(map[string]*alwaysDirectItem)
	alwaysDirectMutex = &sync.RWMutex{}

	ipRange []*ipNetState

	fakeDnsIp4 uint32 = 184549376 // 11.0.0.0

	baseDir string

	cacheFile *os.File

	aclListPath string
	aclRanges   []*iprange.IPV4Range

	started bool
	startWg = &sync.WaitGroup{}

	dialer = &net.Dialer{
		Timeout: dnsTimeout,
		Control: android.DialerControl,
	}
)

func init() {
	startWg.Add(1)
}

func LoggerFunc(f func(f string, v ...interface{})) {
	logf = f
}

func BaseDir(dir string) {
	baseDir = dir
}

func AclListPath(p string) {
	aclListPath = p
}

type dnsError struct {
	rcode int
}

func (e *dnsError) Error() string {
	return fmt.Sprintf("dns error with rcode=%s", dns.RcodeToString[e.rcode])
}

type ipNetState struct {
	*net.IPNet
	state bool
}

type alwaysDirectItem struct {
	ips  []string
	done chan struct{}
}

func Start() {
	started = true
	go start()
}

func start() {
	var chnDns []string
	var overtureVpnConfPath = []string{"overture-vpn.conf", "overture.conf"}
	var overtureConf = struct {
		BindAddress string
		PrimaryDNS  []struct {
			Address string
		}
		AlternativeDNS []struct {
			Address string
		}
		OnlyPrimaryDNS bool
	}{}
	for _, path := range overtureVpnConfPath {
		if b, err := ioutil.ReadFile(path); err == nil {
			if err := json.Unmarshal(b, &overtureConf); err == nil {
				if overtureConf.OnlyPrimaryDNS {
					for _, d := range overtureConf.PrimaryDNS {
						chnDns = append(chnDns, d.Address)
					}
				} else {
					for _, d := range overtureConf.AlternativeDNS {
						chnDns = append(chnDns, d.Address)
					}
				}
			} else {
				logf("parse %s: %v", overtureVpnConfPath, err)
			}
		} else {
			logf("read %s: %v", overtureVpnConfPath, err)
		}
	}
	if len(chnDns) == 0 {
		log.Fatalln("can not get custom dns from overture conf file")
	} else {
		logf("chinadns: %v", chnDns)
	}
	bindAddr = overtureConf.BindAddress
	chinaDNS = chnDns

	readHosts()
	readCache()
	readAclList()

	if err := refreshProbeDnsSrv(); err != nil {
		log.Fatalf("refreshProbeDnsSrv: %v", err)
	}
	startWg.Done()
	srv := dns.Server{
		Addr:    fmt.Sprintf(bindAddr),
		Net:     "udp4",
		Handler: dns.HandlerFunc(dnsHandler),
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("dns listen: %v", err)
	}
}

func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	ok := false
	var q dns.Question
	for i := range r.Question {
		if r.Question[i].Qtype != dns.TypeAAAA {
			q = r.Question[i]
			ok = true
		}
	}
	qName := q.Name
	logf("dns query: %s", q.Name)
	if !ok {
		dns.HandleFailed(w, r)
		return
	}
	if q.Qtype == dns.TypeA {
		if staticIps := lookupStaticHost(qName); len(staticIps) > 0 {
			logf("domain %s found in hosts: %v", qName, staticIps)
			respMsg := fakeRespDnsMsg(r, staticIps)
			w.WriteMsg(respMsg)
			return
		}
	}
	r.Question = []dns.Question{q}
	respMsg := func() *dns.Msg {
		if q.Qtype == dns.TypeA && qName != "" && qName[len(qName)-1] == '.' && strings.Count(qName, ".") == 1 {
			return fakeRespDnsMsg(r, []string{})
		}

		shouldProbe := q.Qtype == dns.TypeA
		alwaysDirectMutex.RLock()
		item := alwaysDirect[qName]
		alwaysDirectMutex.RUnlock()
		if item != nil {
			<-item.done
			return fakeRespDnsMsg(r, item.ips)
		}

		var fakeIp string
		mappingMutex.RLock()
		fakeIp, ok := mapping[qName]
		mappingMutex.RUnlock()
		if ok {
			if fakeIp != "" {
				return fakeRespDnsMsg(r, []string{fakeIp})
			} else {
				shouldProbe = false
			}
		}
		probeCh := make(chan string, 1)
		if shouldProbe {
			go func() {
				defer close(probeCh)
				probeDNSMutex.RLock()
				localProbeDNS := probeDNS
				probeDNSMutex.RUnlock()
				resp, err := directQueryWithMsg(r, localProbeDNS)
				if err != nil {
					return
				}
				if resp.Rcode == dns.RcodeSuccess {
					logf("domain %s polluted", qName)
					probeCh <- insertFakeDnsRecord(qName)
				}
			}()
		} else {
			close(probeCh)
		}
		realCh := make(chan *dns.Msg, 1)
		go func() {
			defer close(realCh)
			resp, err := directQueryWithMsg(r, chinaDNS)
			if err == nil {
				realCh <- resp
			} else {
				realCh <- nil
			}
		}()
		var respMsg *dns.Msg
		select {
		case fakeIp = <-probeCh:
			if fakeIp != "" {
				return fakeRespDnsMsg(r, []string{fakeIp})
			} else {
				respMsg = <-realCh
			}
		case respMsg = <-realCh:
			if shouldProbe {
				fakeIp = <-probeCh
				if fakeIp != "" {
					return fakeRespDnsMsg(r, []string{fakeIp})
				}
			}
		}
		if respMsg == nil {
			respMsg = failedDnsMsg(r)
		} else {
			if respMsg.Rcode == dns.RcodeServerFailure {
				logf("domain %s server failure", qName)
				return fakeRespDnsMsg(r, []string{insertFakeDnsRecord(qName)})
			}
		}
		if respMsg.Rcode == dns.RcodeSuccess {
			var chnAnswers []dns.RR
			var chnACnt int
			for _, answer := range respMsg.Answer {
				answer.Header().Ttl = 3600
				if dnsA, ok := answer.(*dns.A); ok {
					if ShouldDirectConnect(dnsA.A) {
						chnAnswers = append(chnAnswers, dnsA)
						chnACnt++
					}
				} else {
					chnAnswers = append(chnAnswers, answer)
				}
			}
			if chnACnt == 0 {
				if shouldProbe {
					logf("domain %s has no chn ips, fake it", qName)
					respMsg = fakeRespDnsMsg(r, []string{insertFakeDnsRecord(qName)})
				} else {
					// TODO 这里似乎应该重新probe，cdn.jsdelivr.net就遇到了这个情况
				}
			} else {
				respMsg.Answer = chnAnswers
				if shouldProbe {
					insertDirectRecord(qName)
				}
			}
		}
		return respMsg
	}()
	w.WriteMsg(respMsg)
}

func readCache() {
	cachePath := filepath.Join(baseDir, "fakedns.cache")
	var err error
	cacheFile, err = os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Fatalf("open %s: %v", cachePath, err)
	}
	scanner := bufio.NewScanner(cacheFile)
	cnt := 0
	for scanner.Scan() {
		const (
			directDnsQuery       = "0"
			fakeDnsQuery         = "1"
			alwaysDirectDnsQuery = "2"
		)
		var (
			fakeState string
			domain    string
		)
		line := scanner.Text()
		splitted := strings.Split(line, " ")
		switch len(splitted) {
		case 1:
			domain, fakeState = line, fakeDnsQuery
		case 2:
			domain, fakeState = splitted[0], splitted[1]
		default:
		}
		if domain == "" {
			continue
		}
		isIPNet := strings.Contains(domain, "/") || net.ParseIP(domain) != nil
		if isIPNet {
			d := domain
			if !strings.Contains(domain, "/") {
				d += "/32"
			}
			_, cidr, err := net.ParseCIDR(d)
			if err != nil {
				logf("invalid cidr %s: %v", domain, err)
			} else {
				ipRange = append(ipRange, &ipNetState{cidr, fakeState == fakeDnsQuery})
			}
		} else {
			switch fakeState {
			case directDnsQuery:
				mapping[domain] = ""
			case fakeDnsQuery:
				ip := newFakeIp()
				mapping[ip] = domain
				mapping[domain] = ip
			case alwaysDirectDnsQuery:
				AlwaysDirectDomain(domain)
			default:
				logf("invalid state: %s", line)
			}
		}
		cnt++
	}
	logf("loaded %s %d items, err: %v", cachePath, cnt, scanner.Err())
}

func readAclList() {
	if aclListPath == "" {
		return
	}
	aclRanges = parseAcl(aclListPath)
	lessFunc := func(i, j int) bool {
		return aclRanges[i].Start < aclRanges[j].Start
	}
	if !sort.SliceIsSorted(aclRanges, lessFunc) {
		sort.Slice(aclRanges, lessFunc)
	}
	logf("loaded %s %d items", aclListPath, len(aclRanges))
}

func ipv4toInt(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func parseAcl(filename string) []*iprange.IPV4Range {
	var ipranges []*iprange.IPV4Range

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var bypassList bool
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Trim(scanner.Text(), " ")
		if line == "" {
			continue
		}
		if line[0] == '[' {
			if line == "[bypass_list]" {
				bypassList = true
			} else {
				bypassList = false
			}
			continue
		}
		if !bypassList {
			continue
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err == nil {
			ipranges = append(ipranges, &iprange.IPV4Range{Start: ipv4toInt(ipnet.IP), IPNet: ipnet})
		}
	}

	return ipranges
}

func ShouldDirectConnect(ip net.IP) bool {
	for _, i := range ipRange {
		if i.Contains(ip) {
			return !i.state
		}
	}
	if iprange.IPv4Contains(aclRanges, ip) {
		return true
	}
	alwaysDirectMutex.RLock()
	defer alwaysDirectMutex.RUnlock()
	ipStr := ip.String()
	for _, item := range alwaysDirect {
		for _, directIP := range item.ips {
			if ipStr == directIP {
				return true
			}
		}
	}
	return false
}

func insertDirectRecord(domain string) {
	mappingMutex.Lock()
	_, ok := mapping[domain]
	if !ok {
		mapping[domain] = ""
		fmt.Fprintln(cacheFile, domain, "0")
	}
	mappingMutex.Unlock()
	if !ok {
		logf("fakeDns bypass: %s", domain)
	}
}

func insertFakeDnsRecord(domain string) string {
	mappingMutex.Lock()
	ip, ok := mapping[domain]
	if !ok || ip == "" {
		ip = newFakeIp()
		mapping[ip] = domain
		mapping[domain] = ip
		fmt.Fprintln(cacheFile, domain, "1")
	}
	mappingMutex.Unlock()
	logf("fakeDns insert: %s -> %s", domain, ip)
	return ip
}

func newFakeIp() string {
	newIpInt := atomic.AddUint32(&fakeDnsIp4, 1)
	newIpBytes := make([]byte, net.IPv4len)
	binary.BigEndian.PutUint32(newIpBytes, newIpInt)
	return net.IP(newIpBytes).String()
}

func TryReplaceIP2Dom(orig socks.Addr) socks.Addr {
	if !started {
		return orig
	}
	ip, port, _ := net.SplitHostPort(orig.String())
	if net.ParseIP(ip) == nil {
		return orig
	}
	mappingMutex.RLock()
	domain := mapping[ip]
	mappingMutex.RUnlock()
	if domain == "" {
		return orig
	}
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	addr := socks.ParseAddr(net.JoinHostPort(domain, port))
	if addr == nil {
		return orig
	}
	logf("fakeDns replace: %s -> %s", orig, addr)
	return addr
}

func failedDnsMsg(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	return m
}

func fakeRespDnsMsg(r *dns.Msg, ips []string) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)
	m.CheckingDisabled = true
	q := r.Question[0]
	m.Question = []dns.Question{q}
	rrs := make([]dns.RR, len(ips))
	for i, ip := range ips {
		rrs[i] = &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: q.Qtype,
				Ttl:    3600,
				Class:  dns.ClassINET,
			},
			A: net.ParseIP(ip),
		}
	}
	m.Answer = rrs
	return m
}

func directLookup(domain string, dnsSrv []string) ([]string, error) {
	if domain[len(domain)-1] != '.' {
		domain += "."
	}
	if staticIps := lookupStaticHost(domain); len(staticIps) > 0 {
		return staticIps, nil
	}
	logf("direct lookup %s @%v", domain, dnsSrv)
	m := new(dns.Msg)
	m.Id = uint16(atomic.AddUint32(&directLookupId, 1))
	m.Opcode = dns.OpcodeQuery
	m.CheckingDisabled = true
	m.RecursionDesired = true
	m.Question = []dns.Question{
		{
			Name:   domain,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		},
	}
	resp, err := directQueryWithMsg(m, dnsSrv)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, &dnsError{resp.Rcode}
	}
	var ips []string
	for _, answer := range resp.Answer {
		if dnsA, ok := answer.(*dns.A); ok {
			ips = append(ips, dnsA.A.String())
		}
	}
	return ips, nil
}

func directQueryWithMsg(req *dns.Msg, dnsSrvs []string) (resp *dns.Msg, err error) {
	if len(dnsSrvs) == 0 {
		return nil, errors.New("no dns server")
	}
	for _, dnsSrv := range dnsSrvs {
		resp, err = func() (*dns.Msg, error) {
			co := new(dns.Conn)
			if co.Conn, err = dialer.Dial("udp4", dnsSrv); err != nil {
				return nil, err
			}
			defer co.Close()
			co.SetWriteDeadline(time.Now().Add(dnsTimeout))
			if err = co.WriteMsg(req); err != nil {
				return nil, err
			}
			co.SetReadDeadline(time.Now().Add(dnsTimeout))
			return co.ReadMsg()

		}()
		if err == nil {
			if resp.Rcode != dns.RcodeServerFailure {
				break
			}
		}
	}
	return resp, err
}

func refreshProbeDnsSrv() error {
	nsCachePath := filepath.Join(baseDir, "fakedns.ns")

	fetchRemote := func() error {
		const probeSrvCap = 2
		var (
			probeDnsSrvCh = make(chan string, probeSrvCap)

			probeSrvCnt uint32

			wg = &sync.WaitGroup{}

			probeTLDs = []string{"hk", "kr", "jp"}
		)

		for _, probeTLD := range probeTLDs {
			wg.Add(1)
			go func(probeTLD string) {
				defer wg.Done()
				m := new(dns.Msg)
				m.Id = uint16(atomic.AddUint32(&directLookupId, 1))
				m.Opcode = dns.OpcodeQuery
				m.CheckingDisabled = true
				m.RecursionDesired = true
				m.Question = []dns.Question{
					{
						Name:   probeTLD + ".",
						Qtype:  dns.TypeNS,
						Qclass: dns.ClassINET,
					},
				}
				resp, err := directQueryWithMsg(m, chinaDNS)
				if err != nil {
					logf("query NS %s error: %v", probeTLD, err)
					return
				}
				if resp.Rcode != dns.RcodeSuccess {
					logf("query NS %s, rcode=%v", probeTLD, dns.RcodeToString[resp.Rcode])
					return
				}
				var probeNameServers []string
				for _, answer := range resp.Answer {
					if ns, ok := answer.(*dns.NS); ok {
						probeNameServers = append(probeNameServers, ns.Ns)
					}
				}
				if len(probeNameServers) == 0 {
					logf("query NS %s but got none", probeTLD)
					return
				}
				logf("query NS %s: %v", probeTLD, probeNameServers)

				for _, s := range probeNameServers {
					wg.Add(1)
					go func(s string) {
						defer wg.Done()
						if atomic.LoadUint32(&probeSrvCnt) > probeSrvCap {
							return
						}
						ips, err := directLookup(s, chinaDNS)
						if err != nil {
							logf("lookup %s: %v", s, err)
							return
						}
						for _, ip := range ips {
							wg.Add(1)
							go func(ip string) {
								defer wg.Done()
								if atomic.LoadUint32(&probeSrvCnt) > probeSrvCap {
									return
								}
								ip += ":53"
								_, err := directLookup("www.baidu.com", []string{ip})
								logf("probe server %s return: %v", ip, err)
								if err != nil {
									if _, ok := err.(*dnsError); ok {
										if atomic.AddUint32(&probeSrvCnt, 1) <= probeSrvCap {
											probeDnsSrvCh <- ip
										}
									}
								}
							}(ip)
							time.Sleep(20 * time.Millisecond)
						}
					}(s)
					time.Sleep(20 * time.Millisecond)
				}
			}(probeTLD)
		}

		wgCh := make(chan struct{})
		go func() {
			wg.Wait()
			close(wgCh)
		}()
		ips := make([]string, 0, probeSrvCap)
		for i := 0; i < probeSrvCap; i++ {
			var ip string
			select {
			case ip = <-probeDnsSrvCh:
			case <-wgCh:
				select {
				case ip = <-probeDnsSrvCh:
				default:
					i = probeSrvCap
				}
			}
			if ip != "" {
				ips = append(ips, ip)
			}
		}
		if len(ips) == 0 {
			logf("probe dns empty, discard and keep old: %v", probeDNS)
			return nil
		}
		logf("probe dns: %v", ips)
		changed := false
		probeDNSMutex.Lock()
		if len(probeDNS) != len(ips) {
			changed = true
		} else {
			for _, a := range probeDNS {
				found := false
				for _, b := range ips {
					if a == b {
						found = true
						break
					}
				}
				if !found {
					changed = true
					break
				}
			}
		}
		if changed {
			probeDNS = ips
		}
		probeDNSMutex.Unlock()
		if changed {
			ioutil.WriteFile(nsCachePath, []byte(strings.Join(ips, "\n")), 0600)
		}
		return nil
	}

	var ips []string
	nsBytes, _ := ioutil.ReadFile(nsCachePath)
	nsStr := string(nsBytes)
	for _, s := range strings.Split(nsStr, "\n") {
		if host, port, err := net.SplitHostPort(s); err == nil {
			if net.ParseIP(host) != nil {
				if _, err := strconv.Atoi(port); err == nil {
					ips = append(ips, s)
				}
			}
		}
	}
	var err error
	if len(ips) > 0 {
		probeDNSMutex.Lock()
		probeDNS = ips
		probeDNSMutex.Unlock()
		logf("probe name server load from cache: %v", ips)
	} else {
		err = fetchRemote()
	}
	go func() {
		if info, err := os.Stat(nsCachePath); err == nil {
			delta := time.Now().Sub(info.ModTime())
			if delta < 0 {
				delta = 0
			}
			delta = time.Hour - delta
			if delta > 0 {
				time.Sleep(delta)
			}
		}
		for {
			logf("fetchRemote: %v", fetchRemote())
			time.Sleep(time.Hour)
		}
	}()
	return err
}
func AlwaysDirectDomain(domain string) {
	if domain == "" {
		return
	}
	if net.ParseIP(domain) != nil {
		return
	}
	if domain[len(domain)-1] != '.' {
		domain += "."
	}
	_, ok := alwaysDirect[domain]
	if !ok {
		alwaysDirect[domain] = &alwaysDirectItem{
			done: make(chan struct{}),
		}
		mapping[domain] = ""
	}
	if !ok {
		go func(domain string) {
			startWg.Wait()
			interval := time.NewTicker(30 * time.Minute)
			defer interval.Stop()
			retry := time.NewTicker(time.Second)
			defer retry.Stop()
			for {
				ips, err := directLookup(domain, chinaDNS)
				if err != nil {
					logf("direct lookup %s @%v error: %v", domain, chinaDNS, err)
					<-retry.C
				} else {
					alwaysDirectMutex.Lock()
					item := alwaysDirect[domain]
					done := item.done
					select {
					case <-done:
						done = make(chan struct{})
						item = &alwaysDirectItem{
							ips:  ips,
							done: done,
						}
						alwaysDirect[domain] = item
					default:
						item.ips = ips
					}
					alwaysDirectMutex.Unlock()
					close(done)
					<-interval.C
				}
			}
		}(domain)
		logf("fakedns AlwaysDirectDomain %s", domain)
	}
}
