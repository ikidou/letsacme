package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

type Order struct {
	id          string
	certContent []byte

	Certificate *string `json:"certificate,omitempty"`

	Status         string       `json:"status"`
	Expires        string       `json:"expires"`
	NotBefore      string       `json:"notBefore"`
	NotAfter       string       `json:"notAfter"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
}

type Identifier struct {
	id      string
	orderId string
	Type    string `json:"type"`
	Value   string `json:"value"`
}

type CertPair struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

var (
	rootCertPath   = flag.String("ca-cert", "./acme_ca.crt", "CA certificate path")
	rootKeyPath    = flag.String("ca-key", "./acme_ca.key", "CA private key path")
	https          = flag.Bool("https", false, "use HTTPS protocol")
	serverCertPath = flag.String("server-cert", "", "server certificate path (default \"./acme_server.crt\")")
	serverKeyPath  = flag.String("server-key", "", "server private key path (default \"./acme_server.key\")")
	serverName     = flag.String("server-name", "localhost, letsacme.localhost, 127.0.0.1, ::1", "comma-separated server ip or dns name")
	port           = flag.Int("port", 3000, "listen port")
	help           = flag.Bool("help", false, "show help")

	caPair         *CertPair
	serverCertPair *CertPair

	orderMap = make(map[string]*Order) // orderID -> order
)

func main() {
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}
	initCA()

	http.HandleFunc("/acme/directory", handleDirectory)
	http.HandleFunc("/acme/new-nonce", handleNonce)
	http.HandleFunc("/acme/new-account", handleNewAccount)
	http.HandleFunc("/acme/new-order", handleNewOrder)
	http.HandleFunc("/acme/authz/", handleAuthz)
	http.HandleFunc("/acme/finalize/", handleFinalize)
	http.HandleFunc("/acme/order/", handleOrderQuery)
	http.HandleFunc("/acme/cert/", handleDownloadCert)

	http.HandleFunc("/account/default/orders", handleOrders)

	http.HandleFunc("/acme/ca.crt", handleCACert)
	http.HandleFunc("/", handleIndex)

	log.Printf("download CA certificate from localhost:%d/acme/ca.crt", *port)
	log.Println("letsacme started, available at:")
	if *https {
		for _, dns := range serverCertPair.Cert.DNSNames {
			log.Printf("\thttps://%s:%d/acme/directory", dns, *port)
		}
		for _, ip := range serverCertPair.Cert.IPAddresses {
			if len(ip) == net.IPv4len {
				log.Printf("\thttps://%s:%d/acme/directory", ip.String(), *port)
			} else {
				log.Printf("\thttps://%s:%d/acme/directory", "["+ip.String()+"]", *port)
			}
		}
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", *port), *serverCertPath, *serverKeyPath, nil))
	} else {
		log.Printf("\thttp://0.0.0.0:%d/acme/directory", *port)
		log.Printf("\thttp://loalhost:%d/acme/directory", *port)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
	}
}

func handleOrders(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s", r.Method, r.URL.Path)
	orders := make([]string, 0, len(orderMap))

	base := getBaseURL(r)
	for orderId := range orderMap {
		orders = append(orders, base+"/order/"+orderId)
	}
	renderJSON(w, http.StatusOK, map[string]interface{}{
		"orders": orders,
	})
}

func handleDirectory(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s", r.Method, r.URL.Path)
	base := getBaseURL(r)
	renderJSON(w, http.StatusOK, map[string]string{
		"newNonce":   base + "/new-nonce",
		"newAccount": base + "/new-account",
		"newOrder":   base + "/new-order",
	})
}

func handleNonce(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s", r.Method, r.URL.Path)
	w.Header().Set("Replay-Nonce", randomString())

	switch r.Method {
	case "HEAD":
		w.WriteHeader(http.StatusOK)
	case "GET":
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

/**
 * simply return the default account status
 */
func handleNewAccount(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s", r.Method, r.URL.Path)
	base := getBaseURL(r)
	w.Header().Set("Location", base+"/account/default")
	renderJSON(w, http.StatusCreated, map[string]interface{}{
		"status": "valid",
		"orders": base + "/account/default/orders",
	})
}

func handleNewOrder(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s", r.Method, r.URL.Path)
	payload, err := decodeJose(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	base := getBaseURL(r)
	var req struct {
		Identifiers []Identifier `json:"identifiers"`
	}
	json.NewDecoder(strings.NewReader(*payload)).Decode(&req)

	orderId := randomString()
	authorizations := make([]string, 0, len(req.Identifiers))
	domains := make([]string, 0, len(req.Identifiers))
	identifiers := make([]Identifier, 0, len(req.Identifiers))
	for _, identifier := range req.Identifiers {
		identifier.orderId = orderId
		identifier.id = randomString()
		domains = append(domains, identifier.Value)
		identifiers = append(identifiers, identifier)
		authorizations = append(authorizations, base+"/authz/"+identifier.orderId+"/"+identifier.id)
	}
	log.Printf("  domains: %v", domains)

	order := &Order{
		id:             orderId,
		Status:         "ready",
		Expires:        time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		NotBefore:      time.Now().Format(time.RFC3339),
		NotAfter:       time.Now().AddDate(1, 0, 0).Format(time.RFC3339),
		Identifiers:    identifiers,
		Authorizations: authorizations,
		Finalize:       base + "/finalize/" + orderId,
	}
	orderMap[orderId] = order

	w.Header().Set("Location", base+"/order/"+orderId)
	renderJSON(w, http.StatusCreated, order)
}

func handleOrderQuery(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s", r.Method, r.URL.Path)
	id := strings.TrimPrefix(r.URL.Path, "/acme/order/")
	order := orderMap[id]
	if order != nil {
		renderJSON(w, http.StatusOK, order)
	} else {
		renderJSON(w, http.StatusNotFound, make(map[string]string))
	}
}

func handleAuthz(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s", r.Method, r.URL.Path)
	id := strings.TrimPrefix(r.URL.Path, "/acme/authz/")
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		renderJSON(w, http.StatusBadRequest, make(map[string]string))
		return
	}
	orderId := parts[0]
	identifierId := parts[1]
	order := orderMap[orderId]

	if order == nil {
		renderJSON(w, http.StatusNotFound, make(map[string]string))
		return
	}

	var identifier *Identifier
	for _, _identifier := range order.Identifiers {
		if _identifier.id == identifierId {
			identifier = &_identifier
			break
		}
	}
	if identifier == nil {
		renderJSON(w, http.StatusNotFound, make(map[string]string))
		return
	}
	order.Status = "valid"
	renderJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "valid",
		"identifier": identifier,
		"challenges": []map[string]interface{}{
			// {"type": "http-01", "status": "valid", "token": token, "url": getBaseURL(r)+"/"+identifier.OrderId+"/"+identifier.ID},
		},
	})
}

func handleFinalize(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s", r.Method, r.URL.Path)
	id := strings.TrimPrefix(r.URL.Path, "/acme/finalize/")
	order := orderMap[id]

	if order == nil {
		renderJSON(w, http.StatusNotFound, make(map[string]string))
		return
	}

	payload, err := decodeJose(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.NewDecoder(strings.NewReader(*payload)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log.Printf("CSR received, len=%d", len(req.CSR))

	certDer, err := issueCertFromCSR(req.CSR, caPair)
	if err != nil {
		log.Printf("failed to create certificate: %v", err)
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}

	base := getBaseURL(r)
	certURL := base + "/cert/" + order.id

	log.Printf("  cert issued, url=%s", certURL)

	// 存储证书，供 order 轮询使用
	order.certContent = certDer
	order.Certificate = &certURL

	renderJSON(w, http.StatusOK, order)
}

func handleDownloadCert(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s", r.Method, r.URL.Path)
	orderId := strings.TrimPrefix(r.URL.Path, "/acme/cert/")
	order := orderMap[orderId]
	delete(orderMap, orderId)
	if order == nil {
		renderJSON(w, http.StatusNotFound, make(map[string]string))
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("Replay-Nonce", randomString())
	w.WriteHeader(http.StatusOK)
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: order.certContent})
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: caPair.Cert.Raw})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	base := getBaseURL(r)
	w.Header().Set("Content-Type", "text/plain")
	content := fmt.Sprintf("Acme Directory: %s/directory\nCA Certificate: %s/ca.crt", base, base)
	io.WriteString(w, content)
}

func handleCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pem-certificate")
	w.Header().Set("Content-Disposition", "attachment; filename=letsacme_ca.crt")
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: caPair.Cert.Raw})
}

func renderJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", randomString())
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func decodeJose(r io.Reader) (*string, error) {
	var jose struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r).Decode(&jose); err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(jose.Payload)
	if err != nil {
		return nil, err
	}
	s := string(payload)
	return &s, nil
}

func randomString() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func getBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}

	host := r.Host
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}

	return fmt.Sprintf("%s://%s/acme", scheme, host)
}

func absPath(path string) string {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absPath
}

func initCA() {
	var err error
	rootCertFullPath := absPath(*rootCertPath)
	rootKeyFullPath := absPath(*rootKeyPath)
	log.Printf("load CA crt from: %s", rootCertFullPath)
	log.Printf("load CA key from: %s", rootKeyFullPath)
	caPair, err = loadOrCreateCert(rootCertFullPath, rootKeyFullPath, "LetsACME Root CA RSA %s", "RSA", "", nil, false)
	if err != nil {
		log.Fatalf("failed to load root CA: %v", err)
	}
	if !caPair.Cert.IsCA {
		log.Fatalf("%s is not CA cert", *rootCertPath)
	}
	if caPair.Cert.NotBefore.After(time.Now()) || caPair.Cert.NotAfter.Before(time.Now()) {
		log.Fatalf("%s cert date range invalid %s - %s", *rootCertPath, caPair.Cert.NotBefore.Format(time.RFC3339), caPair.Cert.NotAfter.Format(time.RFC3339))
	}
	if !*https {
		return
	}
	if *serverCertPath == "" && *serverKeyPath != "" || *serverCertPath != "" && *serverKeyPath == "" {
		log.Fatalf("server cert path and key path must be both empty or both non-empty")
	}
	if *serverCertPath == "" {
		*serverCertPath = "./acme_server.crt"
		*serverKeyPath = "./acme_server.key"
	}
	serverCertFullPath := absPath(*serverCertPath)
	serverKeyFullPath := absPath(*serverKeyPath)
	log.Printf("load server crt from: %s", serverCertFullPath)
	log.Printf("load server key from: %s", serverKeyFullPath)
	serverCertPair, err = loadOrCreateCert(serverCertFullPath, serverKeyFullPath, "LetsACME Server %s", "ECDSA", *serverName, caPair, false)
	if err != nil {
		log.Fatalf("failed to load server cert: %v", err)
	}
	if serverCertPair.Cert.NotBefore.After(time.Now()) || serverCertPair.Cert.NotAfter.Before(time.Now()) {
		log.Printf("server cert date range invalid %s - %s", serverCertPair.Cert.NotBefore.Format(time.RFC3339), serverCertPair.Cert.NotAfter.Format(time.RFC3339))
	}

	if len(serverCertPair.Cert.DNSNames) == 0 && len(serverCertPair.Cert.IPAddresses) == 0 {
		log.Fatalf("server cert does not have any DNSNames or IPAddresses")
	}
}
