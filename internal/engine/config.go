package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"aurasplit/internal/manifest"
	"aurasplit/internal/profile"
)

// Tags used inside the generated configuration.
const (
	TagTun       = "tun-in"
	TagWG        = "wg"
	TagDirect    = "direct"
	TagWGDirect  = "wg-direct"
	TagDNSRemote = "remote"
	TagDNSLocal  = "local"

	TunInterfaceName = "AuraSplitTR"
	tunIPv4          = "172.19.0.1/30"
	tunIPv6          = "fdfe:dcba:9876::1/126"
	defaultTunMTU    = 1420
	defaultWGMTU     = 1420
	warpWGMTU        = 1280
	defaultRemoteDNS = "1.1.1.1"
	keepaliveSeconds = 25
)

// DiscordPathRegex is generated from the enrollment contract.
var DiscordPathRegex = manifest.PathRegex()

// Fallback rules provide routing only, never verified manifest enrollment.
const DiscordInstallDirectoryRegex = `(?i)\\AppData\\Local\\(?:Discord|DiscordPTB|DiscordCanary|DiscordDevelopment)\\`

const DiscordInstallerRegex = `(?i)\\Discord\w*Setup[^\\]*\.exe$`

var DiscordProcessNames = []string{"Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe", "DiscordDevelopment.exe"}

// DiscordDomains is the Discord-owned domain set (domain_suffix semantics).
// It is tunnelled from every process, so browsers and the installers use the
// tunnel for these names too.
var DiscordDomains = []string{
	"discord.com",
	"discord.gg",
	"discordapp.com",
	"discordapp.net",
	"discord.media",
	"discordcdn.com",
	"discord.co",
	"discord.new",
	"discord.gift",
	"discord.dev",
	"discordstatus.com",
	"discordsays.com",
	"dis.gd",
}

// DiscordHosts are exact host names (domain semantics) outside the Discord
// zones that carry Discord traffic. The parent zone is shared with other
// services and is therefore not tunnelled.
var DiscordHosts = []string{
	"discord-attachments-uploads-prd.storage.googleapis.com",
}

// excludedRoutes never enter the TUN: private LAN, CGNAT, link-local,
// multicast and broadcast ranges.
var excludedRoutes = []string{
	"10.0.0.0/8",
	"100.64.0.0/10",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"224.0.0.0/4",
	"255.255.255.255/32",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// ---- minimal typed mirror of the sing-box 1.14 JSON schema ----

type config struct {
	Log       logOptions      `json:"log"`
	DNS       dnsOptions      `json:"dns"`
	Endpoints []wgEndpoint    `json:"endpoints,omitempty"`
	Inbounds  []tunInbound    `json:"inbounds"`
	Outbounds []plainOutbound `json:"outbounds"`
	Route     routeOptions    `json:"route"`
}

type logOptions struct {
	Disabled  bool   `json:"disabled,omitempty"`
	Level     string `json:"level,omitempty"`
	Output    string `json:"output,omitempty"`
	Timestamp bool   `json:"timestamp,omitempty"`
}

type dnsOptions struct {
	Servers        []dnsServer `json:"servers"`
	Rules          []dnsRule   `json:"rules,omitempty"`
	Final          string      `json:"final"`
	ReverseMapping bool        `json:"reverse_mapping,omitempty"`
}

type dnsServer struct {
	BindInterface string `json:"bind_interface,omitempty"`
	Type          string `json:"type"`
	Tag           string `json:"tag"`
	Server        string `json:"server,omitempty"`
	ServerPort    uint16 `json:"server_port,omitempty"`
	Detour        string `json:"detour,omitempty"`
}

type dnsRule struct {
	ProcessName      []string `json:"process_name,omitempty"`
	ProcessPathRegex []string `json:"process_path_regex,omitempty"`
	Domain           []string `json:"domain,omitempty"`
	DomainSuffix     []string `json:"domain_suffix,omitempty"`
	QueryType        []string `json:"query_type,omitempty"`
	Action           string   `json:"action"`
	Server           string   `json:"server,omitempty"`
	Rcode            string   `json:"rcode,omitempty"`
}

type wgEndpoint struct {
	Type           string   `json:"type"`
	Tag            string   `json:"tag"`
	MTU            uint32   `json:"mtu"`
	Address        []string `json:"address"`
	PrivateKey     string   `json:"private_key"`
	Peers          []wgPeer `json:"peers"`
	Detour         string   `json:"detour,omitempty"`
	DomainResolver string   `json:"domain_resolver"`
}

type wgPeer struct {
	Address             string   `json:"address"`
	Port                uint16   `json:"port"`
	PublicKey           string   `json:"public_key"`
	PreSharedKey        string   `json:"pre_shared_key,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive uint16   `json:"persistent_keepalive_interval,omitempty"`
	Reserved            []uint8  `json:"reserved,omitempty"`
}

type tunInbound struct {
	Type                string   `json:"type"`
	Tag                 string   `json:"tag"`
	InterfaceName       string   `json:"interface_name"`
	Address             []string `json:"address"`
	MTU                 uint32   `json:"mtu"`
	AutoRoute           bool     `json:"auto_route"`
	StrictRoute         bool     `json:"strict_route"`
	Stack               string   `json:"stack"`
	RouteExcludeAddress []string `json:"route_exclude_address"`
}

type plainOutbound struct {
	BindInterface  string `json:"bind_interface,omitempty"`
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	ConnectTimeout string `json:"connect_timeout,omitempty"`
}

type routeOptions struct {
	DefaultInterface      string      `json:"default_interface,omitempty"`
	Rules                 []routeRule `json:"rules"`
	Final                 string      `json:"final"`
	AutoDetectInterface   bool        `json:"auto_detect_interface"`
	DefaultDomainResolver string      `json:"default_domain_resolver"`
}

type routeRule struct {
	Protocol         []string `json:"protocol,omitempty"`
	IPIsPrivate      bool     `json:"ip_is_private,omitempty"`
	ProcessName      []string `json:"process_name,omitempty"`
	ProcessPathRegex []string `json:"process_path_regex,omitempty"`
	Domain           []string `json:"domain,omitempty"`
	DomainSuffix     []string `json:"domain_suffix,omitempty"`
	Action           string   `json:"action"`
	Outbound         string   `json:"outbound,omitempty"`
}

// Mode selects the configuration variant.
type Mode int

const (
	// ModeTunnel is the normal configuration: Discord goes through "wg".
	ModeTunnel Mode = iota
	// ModeBlock is the fail-closed fallback used while the tunnel cannot be
	// started: the same TUN and classification, but Discord traffic and DNS
	// are rejected instead of tunnelled, so Discord never falls back to the
	// direct connection.
	ModeBlock
)

// Default log levels. "warn" keeps ordinary connections and DNS queries out
// of the log; "info" (foreground --debug only) logs every connection.
const (
	LogLevelDefault = "warn"
	LogLevelDebug   = "info"
)

// BuildConfig returns the normal sing-box JSON configuration for p with
// logging to stderr. A host-name endpoint is resolved first; if that fails
// the error wraps ErrEndpointUnresolved. Returned errors never contain key
// material.
func BuildConfig(p *profile.Profile) ([]byte, error) {
	env, err := resolveNetEnv(p, ModeTunnel, true)
	if err != nil {
		return nil, err
	}
	return buildConfig(p, logOptions{Level: LogLevelDefault, Timestamp: true}, ModeTunnel, env)
}

// BuildBlockConfig returns the fail-closed fallback configuration.
func BuildBlockConfig(p *profile.Profile) ([]byte, error) {
	env, err := resolveNetEnv(p, ModeBlock, true)
	if err != nil {
		return nil, err
	}
	return buildConfig(p, logOptions{Level: LogLevelDefault, Timestamp: true}, ModeBlock, env)
}

// ErrEndpointUnresolved means the WireGuard peer host name could not be
// resolved, so no tunnel configuration was built. Run treats it like any
// other preparation error: the fail-closed fallback keeps Discord blocked
// and the tunnel is retried.
var ErrEndpointUnresolved = errors.New("WireGuard endpoint host could not be resolved")

// netEnv is what a configuration depends on outside the profile. It is
// determined right before an instance is prepared.
type netEnv struct {
	egress egressPin
	// hostIPv6 is the host IPv6 capability (hostHasIPv6) the configuration
	// was built for.
	hostIPv6 bool
	// peerAddr is the literal peer IP. Empty only for Check, which builds a
	// configuration that is never started: the endpoint host is then used
	// as written.
	peerAddr string
}

// resolveNetEnv samples the host IPv6 capability and, for ModeTunnel,
// resolves a host-name endpoint to a literal IP (IPv4 preferred, IPv4 only
// on hosts without IPv6). A host-name peer makes sing-box use an
// unconnected listen socket, which was observed live (Bug 3) to be closed
// and re-opened every few seconds without a handshake; a literal IP uses
// the connected path that works. So with strict a failed lookup is an error
// (ErrEndpointUnresolved), never a configuration with the host name.
// Without strict (Check only) the name is kept.
func resolveNetEnv(p *profile.Profile, mode Mode, strict bool) (netEnv, error) {
	env := netEnv{hostIPv6: hostHasIPv6()}
	if mode != ModeTunnel {
		return env, nil
	}
	host, _, err := net.SplitHostPort(p.WireGuard.Endpoint)
	if err != nil || host == "" {
		// buildConfig reports the malformed endpoint.
		return env, nil
	}
	if a, perr := netip.ParseAddr(host); perr == nil {
		env.peerAddr = a.String()
		return env, nil
	}
	ip, rerr := resolvePeerHost(host, !env.hostIPv6)
	if rerr != nil {
		if !strict {
			return env, nil
		}
		return env, fmt.Errorf("%w: %s: %v", ErrEndpointUnresolved, host, rerr)
	}
	env.peerAddr = ip.String()
	return env, nil
}

// remoteDNSAddr is the DNS server used inside the tunnel: the first
// usable profile DNS address (IPv6 only if the tunnel has an IPv6
// address), else defaultRemoteDNS.
func remoteDNSAddr(dns []string, hasIPv6 bool) string {
	for _, d := range dns {
		if a, err := netip.ParseAddr(d); err == nil && (a.Is4() || hasIPv6) {
			return a.String()
		}
	}
	return defaultRemoteDNS
}

// tunnelDNSServer returns host:53 of the in-tunnel DNS server of p (the
// same server the configuration uses for Discord names).
func tunnelDNSServer(p *profile.Profile) string {
	hasIPv6 := false
	for _, a := range p.WireGuard.Addresses {
		if pfx, err := netip.ParsePrefix(a); err == nil && pfx.Addr().Is6() && !pfx.Addr().Is4In6() {
			hasIPv6 = true
		}
	}
	return net.JoinHostPort(remoteDNSAddr(p.WireGuard.DNS, hasIPv6), "53")
}

// buildConfig builds the configuration for p in env (see resolveNetEnv).
// It does no lookups of its own.
func buildConfig(p *profile.Profile, logOpts logOptions, mode Mode, env netEnv) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid profile: %w", err)
	}
	wg := p.WireGuard

	host, portStr, err := net.SplitHostPort(wg.Endpoint)
	if err != nil {
		return nil, errors.New("invalid WireGuard endpoint: expected host:port")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid WireGuard endpoint port")
	}
	if host == "" {
		return nil, errors.New("invalid WireGuard endpoint host")
	}

	hasIPv6 := false
	addresses := make([]string, 0, len(wg.Addresses))
	for _, a := range wg.Addresses {
		pfx, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, fmt.Errorf("invalid interface address %q", a)
		}
		if pfx.Addr().Is6() && !pfx.Addr().Is4In6() {
			hasIPv6 = true
		}
		addresses = append(addresses, pfx.String())
	}

	wgMTU := uint32(defaultWGMTU)
	if p.Provider == profile.ProviderWARP {
		wgMTU = warpWGMTU
	}
	tunMTU := uint32(defaultTunMTU)
	if wg.MTU != 0 {
		wgMTU = uint32(wg.MTU)
		tunMTU = uint32(wg.MTU)
	}

	remoteDNS := remoteDNSAddr(wg.DNS, hasIPv6)

	// The peer is the literal IP resolved by resolveNetEnv (see there why a
	// host name is never used for a tunnel that is started).
	peerHost := host
	if env.peerAddr != "" {
		peerHost = env.peerAddr
	}
	peer := wgPeer{
		Address:             peerHost,
		Port:                uint16(port),
		PublicKey:           wg.PeerPublicKey,
		PreSharedKey:        wg.PresharedKey,
		AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
		PersistentKeepalive: keepaliveSeconds,
	}
	if len(wg.Reserved) == 3 {
		peer.Reserved = []uint8{wg.Reserved[0], wg.Reserved[1], wg.Reserved[2]}
	}

	// Routing fallbacks are separate from the verified enrollment contract.
	processNames := append(append([]string{}, DiscordProcessNames...), p.ExtraProcessNames...)
	pathRegex := []string{manifest.PathRegex(), DiscordInstallDirectoryRegex, DiscordInstallerRegex}

	// discord is the action applied to classified Discord traffic.
	discord := routeRule{Action: "route", Outbound: TagWG}
	discordDNS := dnsRule{Action: "route", Server: TagDNSRemote}
	if mode == ModeBlock {
		discord = routeRule{Action: "reject"}
		discordDNS = dnsRule{Action: "reject"}
	}
	withRoute := func(r routeRule) routeRule {
		r.Action, r.Outbound = discord.Action, discord.Outbound
		return r
	}
	withDNS := func(r dnsRule) dnsRule {
		r.Action, r.Server, r.Rcode = discordDNS.Action, discordDNS.Server, discordDNS.Rcode
		return r
	}

	// The Discord domain list is tunnelled from every process (browsers,
	// installers started by any parent), not only from Discord itself.
	routeRules := []routeRule{
		{Action: "sniff"},
		{Protocol: []string{"dns"}, Action: "hijack-dns"},
		{IPIsPrivate: true, Action: "route", Outbound: TagDirect},
		withRoute(routeRule{ProcessPathRegex: pathRegex}),
	}
	if len(processNames) > 0 {
		routeRules = append(routeRules, withRoute(routeRule{ProcessName: processNames}))
	}
	routeRules = append(routeRules, withRoute(routeRule{Domain: DiscordHosts, DomainSuffix: DiscordDomains}))

	// DNS: on Windows most lookups come from the DNS Client service, so the
	// process rules only catch apps with their own resolver; the domain rule
	// is what guarantees the listed Discord names never reach the ISP
	// resolver.
	hostV6 := env.hostIPv6
	// Only give the TUN an IPv6 address (and therefore an IPv6 default
	// route) when the host itself has IPv6. Otherwise applications that
	// resolve AAAA records on their own (browser DoH) would connect over
	// IPv6 into the TUN, the stack would accept the connection and the
	// direct outbound would then fail, which browsers report as "offline"
	// instead of falling back to IPv4.
	tunAddresses := []string{tunIPv4}
	if hostV6 {
		tunAddresses = append(tunAddresses, tunIPv6)
	}
	var dnsRules []dnsRule
	if !hostV6 {
		// The host has no IPv6 egress (no interface with both a global
		// IPv6 address and an IPv6 default route). Without this, clients
		// could still try IPv6 first for names they resolve through the
		// hijacked resolver, the direct outbound would fail with WSAEINVAL
		// and they would only fall back to IPv4 after a delay. Answer every
		// AAAA query with an empty NOERROR.
		dnsRules = append(dnsRules, dnsRule{QueryType: []string{"AAAA"}, Action: "predefined", Rcode: "NOERROR"})
	}
	if !hasIPv6 && mode == ModeTunnel {
		// The tunnel has no IPv6 address: answer AAAA for tunnelled names
		// with an empty NOERROR so clients use IPv4 immediately.
		aaaa := dnsRule{QueryType: []string{"AAAA"}, Action: "predefined", Rcode: "NOERROR"}
		r1, r2, r3 := aaaa, aaaa, aaaa
		r1.ProcessPathRegex = pathRegex
		r2.ProcessName = processNames
		r3.Domain, r3.DomainSuffix = DiscordHosts, DiscordDomains
		dnsRules = append(dnsRules, r1)
		if len(processNames) > 0 {
			dnsRules = append(dnsRules, r2)
		}
		dnsRules = append(dnsRules, r3)
	}
	dnsRules = append(dnsRules, withDNS(dnsRule{ProcessPathRegex: pathRegex}))
	if len(processNames) > 0 {
		dnsRules = append(dnsRules, withDNS(dnsRule{ProcessName: processNames}))
	}
	dnsRules = append(dnsRules, withDNS(dnsRule{Domain: DiscordHosts, DomainSuffix: DiscordDomains}))

	servers := []dnsServer{{Type: "local", Tag: TagDNSLocal, BindInterface: env.egress.alias}}
	var endpoints []wgEndpoint
	if mode == ModeTunnel {
		servers = append([]dnsServer{{Type: "udp", Tag: TagDNSRemote, Server: remoteDNS, ServerPort: 53, Detour: TagWG}}, servers...)
		endpoints = []wgEndpoint{{
			Type:       "wireguard",
			Tag:        TagWG,
			MTU:        wgMTU,
			Address:    addresses,
			PrivateKey: wg.PrivateKey,
			Peers:      []wgPeer{peer},
			// Dial the peer through a dedicated, non-empty direct outbound.
			// Without a detour sing-box uses wireguard-go's StdNetBind, which
			// always opens an IPv6 socket bound to the physical interface;
			// on hosts where IPv6 is unbound from that adapter this fails
			// with WSAEINVAL and the whole bind (IPv4 too) is lost, so no
			// handshake ever happens. With a detour sing-box uses its
			// ClientBind, which only opens the socket family of the peer.
			Detour:         TagWGDirect,
			DomainResolver: TagDNSLocal, // resolve the peer host outside the tunnel
		}}
	}
	outbounds := []plainOutbound{{Type: "direct", Tag: TagDirect}}
	if mode == ModeTunnel {
		// connect_timeout makes the outbound "non-empty"; sing-box refuses
		// a detour to an empty direct outbound.
		outbounds = append(outbounds, plainOutbound{Type: "direct", Tag: TagWGDirect, ConnectTimeout: "10s"})
	}
	for j := range outbounds {
		outbounds[j].BindInterface = env.egress.alias
	}

	cfg := config{
		Log: logOpts,
		DNS: dnsOptions{
			Servers: servers,
			Rules:   dnsRules,
			Final:   TagDNSLocal,
			// Lets route rules match Discord domains on connections whose
			// host name cannot be sniffed (e.g. by IP after a DNS answer).
			ReverseMapping: true,
		},
		Endpoints: endpoints,
		Inbounds: []tunInbound{{
			Type:                "tun",
			Tag:                 TagTun,
			InterfaceName:       TunInterfaceName,
			Address:             tunAddresses,
			MTU:                 tunMTU,
			AutoRoute:           true,
			StrictRoute:         true, // blocks DNS on other interfaces (leak protection)
			Stack:               "mixed",
			RouteExcludeAddress: excludedRoutes,
		}},
		Outbounds: outbounds,
		Route: routeOptions{
			Rules:                 routeRules,
			Final:                 TagDirect,
			AutoDetectInterface:   env.egress.index == 0,
			DefaultInterface:      env.egress.alias,
			DefaultDomainResolver: TagDNSLocal,
		},
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, errors.New("encode sing-box config failed")
	}
	return out, nil
}
