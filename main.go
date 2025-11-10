package main

import (
	"context"
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// A web version of Marek's script

var (
	SSDP_SEARCH_P = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: %s\r\n\r\n"
	SERVER_RE     = regexp.MustCompile("(?i)server: ?([^\r\n]*)[\r\n]")
	ST_RE         = regexp.MustCompile("(?i)st: ?([^\r\n]*)[\r\n]")

	listenAddr      string
	httplistenAddr  string
	httpslistenAddr string
	protocol        string
	ssdpST          string
	cloudflareMode  bool
	tlsHostname     string
	acmeEMail       string
	conn            *net.UDPConn
	nrequestchan    chan notifyRequest
)

func init() {
	flag.StringVar(&listenAddr, "udplisten", "0.0.0.0:0", "Listen address")
	flag.StringVar(&httplistenAddr, "httplisten", "0.0.0.0:80", "Listen address")
	flag.StringVar(&httpslistenAddr, "httpslisten", "0.0.0.0:443", "Listen address")
	flag.StringVar(&protocol, "p", "udp", "udp/udp4/udp6")
	flag.BoolVar(&cloudflareMode, "cf", false, "Cloudflare header mode")
	flag.StringVar(&tlsHostname, "tls.name", "badupnp.benjojo.co.uk", "What TLS hostname to request from let's encrypt")
	flag.StringVar(&acmeEMail, "acme.email", "", "")
}

//go:embed public/*
var publicDir embed.FS

func main() {
	flag.Parse()
	if acmeEMail == "" {
		log.Fatalf("Set -acme.email")
	}

	addr, err := net.ResolveUDPAddr(protocol, listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	conn, err = net.ListenUDP(protocol, addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	nrequestchan = make(chan notifyRequest)
	go resultCollector(nrequestchan)

	publicDirMinusPublic, _ := fs.Sub(publicDir, "public")
	servablePublicDir := http.FS(publicDirMinusPublic)

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(servablePublicDir))
	mux.HandleFunc("/test", testClient)
	httpsSrv := http.Server{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}

	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			if host == tlsHostname {
				return nil
			}
			return fmt.Errorf("Hostname %s is not an allowed hostname", host)
		},
		Cache: autocert.DirCache("."),
		Email: acmeEMail,
	}
	httpsSrv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			// remove/add not default ports from req.Host
			target := "https://" + r.Host + r.URL.Path
			if len(r.URL.RawQuery) > 0 {
				target += "?" + r.URL.RawQuery
			}
			ipaddr := r.Header.Get("CF-Connecting-IP")

			if ipaddr != "" {
				log.Printf("redirect (CF) to: %s", target)
			} else {
				log.Printf("redirect to: %s", target)
			}
			http.Redirect(rw, r, target,
				// see @andreiavrammsd comment: often 307 > 301
				http.StatusTemporaryRedirect)
		})
		s := &http.Server{
			Handler: m.HTTPHandler(mux),
			Addr:    httplistenAddr,
		}

		go s.ListenAndServe()
	}()

	err = httpsSrv.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("httpsSrv.ListendAndServeTLS() failed with %s", err)
	}
}

type notifyRequest struct {
	ip string
	c  chan bool
}

func testClient(w http.ResponseWriter, rw *http.Request) {
	SSDP_SEARCH := []byte(fmt.Sprintf(SSDP_SEARCH_P, ssdpST))

	ipaddr := rw.RemoteAddr
	if cloudflareMode {
		ipaddr = rw.Header.Get("CF-Connecting-IP")
		if strings.Contains(ipaddr, ":") {
			ipaddr = fmt.Sprintf("[%s]", ipaddr)
		}
	} else {
		ipaddr, _, _ = net.SplitHostPort(ipaddr)
	}

	addr, err := net.ResolveUDPAddr(protocol, fmt.Sprintf("%s:1900", ipaddr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ ] Can't resolve %s\n", ipaddr)
		http.Error(w, "Unable to resolve IP", http.StatusInternalServerError)
		return
	}

	notifyChan := make(chan bool)
	request := notifyRequest{
		ip: rw.Header.Get("CF-Connecting-IP"),
		c:  notifyChan,
	}

	_, err = conn.WriteToUDP(SSDP_SEARCH, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ ] write(%s) failed: %s\n", rw.Header.Get("CF-Connecting-IP"), err)
		http.Error(w, "Unable to produce packet", http.StatusInternalServerError)
		return
	}
	nrequestchan <- request

	select {
	case <-notifyChan:
		w.Write([]byte(`{"result":true}`))
	case <-time.After(time.Second * 5):
		w.Write([]byte(`{"result":false}`))
	}

	close(notifyChan)
}

func resultCollector(notifyrequests chan notifyRequest) {

	waiting := make(map[string]notifyRequest)
	requestlock := sync.Mutex{}

	go func() {
		for r := range notifyrequests {
			requestlock.Lock()

			waiting[r.ip] = r

			requestlock.Unlock()
		}
	}()

	for {
		var buf [2048]byte
		n, remote, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ ] read(): %s\n", err)
			continue
		}
		data := buf[:n]
		m := SERVER_RE.FindAllSubmatch(data, -1)
		server := []byte{}
		if len(m) > 0 && len(m[0]) > 1 {
			server = m[0][1]
		}

		m = ST_RE.FindAllSubmatch(data, -1)
		st := []byte{}
		if len(m) > 0 && len(m[0]) > 1 {
			st = m[0][1]
		}

		sport := 0
		if remote.Port == 1900 {
			sport = 1
		}
		fmt.Printf("%s\t%d\t%d\t%s\t%s\n", remote.IP, n, sport, st, server)

		select {
		case waiting[remote.IP.String()].c <- true:
		default:
		}

		delete(waiting, remote.IP.String())

	}
}
