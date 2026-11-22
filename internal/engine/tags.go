package engine

import "errors"

// SingBoxVersion is the pinned sing-box module version.
const SingBoxVersion = "v1.14.4"

// BuildTags are the Go build tags the binary is compiled with.
// with_gvisor and with_wireguard are required (see tagsOK);
// with_external_windivert only stops sing-box from embedding the WinDivert
// kernel driver, which this program never loads (no tls-spoof, no bridge).
const BuildTags = "with_gvisor,with_wireguard,with_external_windivert"

// ErrMissingBuildTags is returned by Check and Run when the binary was not
// compiled with BuildTags.
var ErrMissingBuildTags = errors.New("engine: binary built without required tags (" + BuildTags + ")")
