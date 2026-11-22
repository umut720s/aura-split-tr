// Package engine turns a profile.Profile into a sing-box configuration and
// runs sing-box as an embedded library (no external process).
//
// Pinned dependency: github.com/sagernet/sing-box v1.14.4 (see SingBoxVersion).
// The generated configuration uses the 1.12+ formats only: WireGuard is an
// endpoint, DNS servers are typed, and sniffing / DNS hijacking are route rule
// actions. Nothing deprecated is emitted (the tests assert this).
//
// Required build tags (see BuildTags):
//
//	with_gvisor     userspace network stack; needed by the "mixed" TUN stack
//	                and by the non-system (userspace) WireGuard endpoint.
//	with_wireguard  registers the WireGuard endpoint.
//	with_external_windivert
//	                optional: sing-box then does not embed the WinDivert
//	                driver (only used by features this program never
//	                enables); without it the binary is about 90 KB larger.
//
// Build example:
//
//	go build -trimpath -buildvcs=false -tags with_gvisor,with_wireguard,with_external_windivert ./cmd/aurasplit
//
// Without these tags the package still compiles, but Check and Run return
// ErrMissingBuildTags.
//
// Traffic policy:
//   - Processes under %LOCALAPPDATA%\Discord* (including Update.exe), the
//     Discord clients by name (Discord.exe, DiscordPTB.exe, DiscordCanary.exe,
//     DiscordDevelopment.exe), installers matching DiscordInstallerRegex and
//     the profile's extra process names are routed to the "wg" endpoint.
//   - Every listed Discord domain (DiscordDomains, DiscordHosts) goes to "wg"
//     from any process, browsers included. The profile's legacy
//     TunnelBrowserDiscord field no longer changes anything.
//   - Everything else uses "direct"; LAN/link-local/multicast never enter TUN.
//   - DNS queries for the listed Discord domains (and from Discord processes,
//     where the source process is visible) are answered by a resolver reached
//     through the tunnel; DNS reverse mapping lets route rules recognise
//     those names on connections that cannot be sniffed. All other names use
//     the system ("local") resolver.
//   - If the tunnel cannot start, Run switches to ModeBlock (same TUN, the
//     Discord rules reject instead of tunnelling) and keeps retrying. A retry
//     resolves the endpoint and creates the next tunnel instance while the
//     fallback still runs; the fallback is closed only right before the
//     prepared tunnel is started (two TUN instances cannot run at once).
//   - sing-box log output goes through a bounded, non-blocking queue
//     (logpump.go) so a slow log sink never stalls sing-box.
package engine
