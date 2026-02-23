// forsale-mcp: A lightweight MCP server for checking domain _for-sale DNS records.
//
// Implements the Model Context Protocol (MCP) using Streamable HTTP transport
// (the modern standard, superseding SSE-based transport).
//
// Based on: draft-davids-forsalereg (https://datatracker.ietf.org/doc/html/draft-davids-forsalereg)
//
// DNS resolution uses net.LookupTXT from the Go standard library. This delegates
// to the OS resolver, which handles EDNS0 and TCP fallback transparently, and
// returns TXT strings as proper Go strings (correct UTF-8, no escaped presentation
// format like \240\159\152\128 that miekg/dns would produce).
//
// Usage:
//
//	go run main.go              # listens on :8082
//	go run main.go -addr :9090  # custom port
//
// MCP endpoint: POST /mcp
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/idna"
)

// ---------------------------------------------------------------------------
// MCP protocol types (minimal, spec-compliant subset)
// ---------------------------------------------------------------------------

type JSONRPCRequest struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Result  interface{}      `json:"result,omitempty"`
	Error   *JSONRPCError    `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	errParse    = -32700
	errInvalid  = -32600
	errNotFound = -32601
	errParams   = -32602
)

var verbose bool

// vlog logs only when -v is set. Format is compact: one line per event.
func vlog(format string, args ...any) {
	if verbose {
		log.Printf("[v] "+format, args...)
	}
}

// fmtID returns a human-readable string for a JSON-RPC ID (*json.RawMessage).
func fmtID(id *json.RawMessage) string {
	if id == nil {
		return "null"
	}
	return string(*id)
}

// ---------------------------------------------------------------------------
// MCP schema types
// ---------------------------------------------------------------------------

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InitializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	ServerInfo      ServerInfo     `json:"serverInfo"`
	Capabilities    map[string]any `json:"capabilities"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required,omitempty"`
}

type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type CallToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ---------------------------------------------------------------------------
// _for-sale parsing (draft-davids-forsalereg)
// ---------------------------------------------------------------------------

const forsaleVersion = "v=FORSALE1;"

// sidnRDAPResponse holds the relevant fields from the SIDN RDAP API response.
// Endpoint: GET https://api.sidn.nl/rdap/whois?domain=<punycode>
type sidnRDAPResponse struct {
	Details struct {
		Domain     string `json:"domain"`
		ForSaleURL string `json:"forSaleUrl"`
	} `json:"details"`
}

// fetchSIDNForSaleURL queries the SIDN RDAP API for the registrar landing page
// URL associated with an NLFS- fcod code. Returns "" (no error) if the domain
// has no forSaleUrl or if the API is unavailable — callers treat this as
// "no extra info available" rather than a hard failure.
//
// The returned URL already contains the domain as a query parameter, matching
// the behaviour of the forsale-web reference implementation.
func fetchSIDNForSaleURL(ctx context.Context, punycode string) string {
	apiURL := "https://api.sidn.nl/rdap/whois?domain=" + url.QueryEscape(punycode)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "forsale-mcp/1.0 (MCP server; draft-davids-forsalereg)")
	req.Header.Set("Accept", "application/json")

	vlog("rdap query %s", punycode)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var rdap sidnRDAPResponse
	if err := json.Unmarshal(body, &rdap); err != nil {
		return ""
	}

	// Safety check: verify the response is actually for the domain we asked.
	if !strings.EqualFold(rdap.Details.Domain, punycode) {
		return ""
	}

	if rdap.Details.ForSaleURL == "" {
		vlog("rdap result %s: no landing URL", punycode)
		return ""
	}
	vlog("rdap result %s: landing URL found", punycode)

	// Append the domain as a query parameter, as the reference implementation does.
	return rdap.Details.ForSaleURL + "?domain=" + url.QueryEscape(punycode)
}

// ForSaleRecord represents one parsed _for-sale TXT record.
type ForSaleRecord struct {
	Raw   string
	Tag   string // fcod | ftxt | furi | fval | "" (version-only)
	Val   string
	Valid bool
}

// ForSaleCode holds a parsed fcod value, with an optional SIDN landing page URL
// for codes that carry the NLFS- prefix.
type ForSaleCode struct {
	Code       string // raw fcod value
	LandingURL string // non-empty for NLFS- codes with a known SIDN landing page
}

// ForSaleResult is the aggregated result for a domain.
type ForSaleResult struct {
	Domain    string
	IsForSale bool
	Records      []ForSaleRecord
	Prices       []string      // fval values
	URIs         []string      // furi values
	Texts        []string      // ftxt values
	Codes        []ForSaleCode // fcod values, enriched for NLFS- codes
	Warnings     []string      // draft conformance warnings
	Error        string
}

var reFval = regexp.MustCompile(`^[A-Z]+\d+(\.\d+)?$`)

// validateRecord checks a parsed record for draft-davids-forsalereg conformance
// and returns a warning string if something is off, or "" if all is fine.
// Kept intentionally simple: we flag the most meaningful violations only.
func validateRecord(raw string) string {
	// §2.4: RDATA must be a single character-string ≤255 octets.
	if len(raw) > 255 {
		return fmt.Sprintf("record exceeds 255 octets (%d bytes)", len(raw))
	}

	if !strings.HasPrefix(raw, forsaleVersion) {
		return "" // not our record, nothing to say
	}
	content := raw[len(forsaleVersion):]

	// §2.1: at most one tag=value pair per record — detect a second semicolon
	// followed by a known tag, which is the nohats.ca anti-pattern.
	if idx := strings.Index(content, ";"); idx >= 0 {
		after := content[idx+1:]
		for _, known := range []string{"fcod=", "ftxt=", "furi=", "fval="} {
			if strings.HasPrefix(after, known) {
				return "multiple tags in one record (§2.1); only one tag=value pair allowed per TXT record"
			}
		}
	}

	// Tag-specific checks.
	switch {
	case strings.HasPrefix(content, "fval="):
		val := content[len("fval="):]
		if !reFval.MatchString(val) {
			return fmt.Sprintf("invalid fval syntax %q; expected e.g. EUR1500 or USD9.99 (§2.2.4)", val)
		}
	case strings.HasPrefix(content, "furi="):
		val := content[len("furi="):]
		scheme := strings.ToLower(strings.SplitN(val, ":", 2)[0])
		recommended := map[string]bool{"http": true, "https": true, "mailto": true, "tel": true}
		if !recommended[scheme] {
			return fmt.Sprintf("furi scheme %q is not recommended (§2.2.3); use http/https/mailto/tel", scheme)
		}
	}
	return ""
}

func parseRecord(raw string) ForSaleRecord {
	r := ForSaleRecord{Raw: raw}
	if !strings.HasPrefix(raw, forsaleVersion) {
		return r // Valid stays false — not a forsale record
	}
	r.Valid = true
	content := raw[len(forsaleVersion):]
	if content == "" {
		return r // Version-only: domain is for sale, no tag
	}
	eqIdx := strings.Index(content, "=")
	if eqIdx < 0 {
		return r // Malformed content; still a valid sale indicator
	}
	r.Tag = content[:eqIdx]
	r.Val = content[eqIdx+1:]
	return r
}

// checkForSale performs the _for-sale lookup for a domain.
//
// net.LookupTXT is used deliberately — the OS resolver handles EDNS0 and TCP
// fallback transparently, and returns TXT strings as proper UTF-8, avoiding
// the escaped \DDD presentation format that miekg/dns produces.
// IDN input is converted to ACE/Punycode via golang.org/x/net/idna (IDNA 2008).
func checkForSale(ctx context.Context, domain string) ForSaleResult {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	result := ForSaleResult{Domain: domain}

	// IDN: convert to Punycode for DNS lookups.
	punycode, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		punycode = strings.ToLower(domain)
	}

	// §2.6 Note 2: ignore _for-sale under .arpa.
	if strings.HasSuffix(strings.TrimSuffix(punycode, "."), ".arpa") {
		result.Error = "domain is under .arpa; _for-sale records must be ignored per draft-davids-forsalereg §2.6"
		return result
	}

	vlog("dns lookup _for-sale.%s", punycode)
	txts, err := net.DefaultResolver.LookupTXT(ctx, "_for-sale."+punycode)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			vlog("dns result _for-sale.%s: NXDOMAIN", punycode)
			return result // not for sale, no error
		}
		vlog("dns error _for-sale.%s: %v", punycode, err)
		result.Error = fmt.Sprintf("DNS query failed: %v", err)
		return result
	}
	vlog("dns result _for-sale.%s: NOERROR, %d TXT record(s)", punycode, len(txts))

	for _, txt := range txts {
		rec := parseRecord(txt)
		if !rec.Valid {
			continue
		}
		result.IsForSale = true
		result.Records = append(result.Records, rec)
		if w := validateRecord(txt); w != "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("record %q: %s", txt, w))
			vlog("conformance warning %s: %s", punycode, w)
		}
		switch rec.Tag {
		case "fval":
			result.Prices = append(result.Prices, rec.Val)
		case "furi":
			result.URIs = append(result.URIs, rec.Val)
		case "ftxt":
			result.Texts = append(result.Texts, rec.Val)
		case "fcod":
			fc := ForSaleCode{Code: rec.Val}
			if strings.HasPrefix(rec.Val, "NLFS-") {
				fc.LandingURL = fetchSIDNForSaleURL(ctx, punycode)
			}
			result.Codes = append(result.Codes, fc)
		}
	}
	return result
}

func formatResult(r ForSaleResult) string {
	if r.Error != "" {
		return fmt.Sprintf("Error checking %q: %s", r.Domain, r.Error)
	}
	if !r.IsForSale {
		return fmt.Sprintf("Domain %q has no _for-sale records or does not exist (NXDOMAIN).", r.Domain)
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Domain %q IS available (marked for sale in DNS).\n", r.Domain))
	if len(r.Prices) > 0 {
		sb.WriteString("Asking price(s): " + strings.Join(r.Prices, ", ") + "\n")
	}
	if len(r.URIs) > 0 {
		sb.WriteString("Contact/info URI(s): " + strings.Join(r.URIs, ", ") + "\n")
	}
	if len(r.Texts) > 0 {
		sb.WriteString("Additional info: " + strings.Join(r.Texts, " | ") + "\n")
	}
	if len(r.Codes) > 0 {
		for _, fc := range r.Codes {
			if fc.LandingURL != "" {
				sb.WriteString(fmt.Sprintf("Registry code: %s (SIDN landing page: %s)\n", fc.Code, fc.LandingURL))
			} else {
				sb.WriteString(fmt.Sprintf("Registry code: %s\n", fc.Code))
			}
		}
	}
	if len(r.Warnings) > 0 {
		sb.WriteString("Conformance warnings:\n")
		for _, w := range r.Warnings {
			sb.WriteString("  ⚠ " + w + "\n")
		}
	}
	sb.WriteString(fmt.Sprintf("Raw records (%d):\n", len(r.Records)))
	for _, rec := range r.Records {
		sb.WriteString("  " + rec.Raw + "\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

// ---------------------------------------------------------------------------
// MCP tool definitions
// ---------------------------------------------------------------------------

var tools = []Tool{
	{
		Name:        "check_for_sale",
		Description: "Check whether a domain name is for sale by querying its _for-sale DNS TXT records (draft-davids-forsalereg). Returns sale status, asking price, contact URIs, and any additional information found in the DNS records.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"domain": {
					Type:        "string",
					Description: `The domain name to check, e.g. "example.co.nl" or "vitesse.arnhem.nl.eu.org"`,
				},
			},
			Required: []string{"domain"},
		},
	},
	{
		Name:        "check_for_sale_bulk",
		Description: "Check multiple domain names for sale status in a single call. Returns results for each domain.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"domains": {
					Type:        "string",
					Description: `Comma-separated list of domain names to check, e.g. "example.co.nl,bitfire.nl,sidnlabs.nl"`,
				},
			},
			Required: []string{"domains"},
		},
	},
}

// ---------------------------------------------------------------------------
// MCP request dispatcher
// ---------------------------------------------------------------------------

func handleInitialize(_ json.RawMessage) (interface{}, *JSONRPCError) {
	return InitializeResult{
		ProtocolVersion: "2024-11-05",
		ServerInfo:      ServerInfo{Name: "forsale-mcp", Version: "1.0.0"},
		Capabilities:    map[string]any{"tools": map[string]any{}},
	}, nil
}

func handleToolsList(_ json.RawMessage) (interface{}, *JSONRPCError) {
	return ToolsListResult{Tools: tools}, nil
}

func handleToolsCall(ctx context.Context, params json.RawMessage) (interface{}, *JSONRPCError) {
	var p CallToolParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &JSONRPCError{Code: errParams, Message: "invalid params: " + err.Error()}
	}
	switch p.Name {
	case "check_for_sale":
		var args struct {
			Domain string `json:"domain"`
		}
		if err := json.Unmarshal(p.Arguments, &args); err != nil || args.Domain == "" {
			return nil, &JSONRPCError{Code: errParams, Message: "missing or invalid 'domain' argument"}
		}
		vlog("tools/call check_for_sale domain=%s", args.Domain)
		r := checkForSale(ctx, args.Domain)
		return CallToolResult{Content: []ToolContent{{Type: "text", Text: formatResult(r)}}}, nil

	case "check_for_sale_bulk":
		var args struct {
			Domains string `json:"domains"`
		}
		if err := json.Unmarshal(p.Arguments, &args); err != nil || args.Domains == "" {
			return nil, &JSONRPCError{Code: errParams, Message: "missing or invalid 'domains' argument"}
		}
		vlog("tools/call check_for_sale_bulk domains=%s", args.Domains)
		var sb strings.Builder
		for i, d := range strings.Split(args.Domains, ",") {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if i > 0 {
				sb.WriteString("\n---\n")
			}
			sb.WriteString(formatResult(checkForSale(ctx, d)))
		}
		return CallToolResult{Content: []ToolContent{{Type: "text", Text: sb.String()}}}, nil

	default:
		return nil, &JSONRPCError{Code: errNotFound, Message: fmt.Sprintf("unknown tool: %q", p.Name)}
	}
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

// healthHandler is not part of the MCP spec but useful for monitoring/loadbalancers.
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "server": "forsale-mcp"})
}

func mcpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, nil, errParse, "parse error: "+err.Error())
		return
	}
	if req.JSONRPC != "2.0" {
		writeError(w, req.ID, errInvalid, `jsonrpc must be "2.0"`)
		return
	}

	ctx := r.Context()
	var result interface{}
	var rpcErr *JSONRPCError

	if req.Method != "tools/call" {
		vlog("method=%s", req.Method)
	}
	switch req.Method {
	case "initialize":
		result, rpcErr = handleInitialize(req.Params)
	case "notifications/initialized":
		w.WriteHeader(http.StatusNoContent)
		return
	case "tools/list":
		result, rpcErr = handleToolsList(req.Params)
	case "tools/call":
		result, rpcErr = handleToolsCall(ctx, req.Params)
	case "ping":
		result = map[string]any{}
	default:
		rpcErr = &JSONRPCError{Code: errNotFound, Message: fmt.Sprintf("method not found: %q", req.Method)}
	}

	resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, id *json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &JSONRPCError{Code: code, Message: msg},
	})
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	addr := flag.String("addr", ":8082", "listen address")
	flag.BoolVar(&verbose, "v", false, "verbose logging")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", mcpHandler)
	mux.HandleFunc("/health", healthHandler) // non-standard, for monitoring

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		BaseContext:  func(net.Listener) context.Context { return context.Background() },
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("forsale-mcp listening on %s (POST /mcp)", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-stop
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	log.Println("stopped.")
}
