# Trademarks and official builds

## Third-party names

AURA Split TR is an independent open-source project. It is **not affiliated
with, endorsed by, sponsored by or supported by** any of the companies or
projects below. Their names are used only to describe what the software works
with (nominative use).

| Name | Owner |
|---|---|
| Discord | Discord Inc. |
| Proton, Proton VPN | Proton AG |
| Cloudflare, WARP, 1.1.1.1 | Cloudflare, Inc. |
| WireGuard | "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. |
| Wintun | WireGuard LLC (project name; see the Wintun license) |
| sing-box | The sing-box project / SagerNet. The sing-box license states that no derivative work may use its name or imply association without prior consent. |
| Windows | Microsoft Corporation |

All other names and logos belong to their respective owners. No logos of these
companies are included in this repository or in the binary.

## The name "AURA Split TR"

"AURA Split TR" is the name of this project. **No trademark registration is
claimed** for it. The GPL-3.0-or-later license grants rights to the code; it
does not grant rights to use the project name to describe a modified version
(GPLv3 section 7(e)).

## Official vs. third-party builds

An **official build** is one that:

1. was built by this repository's `.github/workflows/release.yml` from a
   tagged commit of `https://github.com/umut720s/aura-split-tr`,
2. is attached to a release on that repository that a maintainer published by
   hand, and
3. matches the `SHA256SUMS.txt` of that release and has a valid GitHub build
   provenance attestation (`gh attestation verify aurasplit.exe --repo umut720s/aura-split-tr`).

Official builds are currently **not Authenticode-signed**.

Anything else is a **third-party build**, including builds you make yourself
from the same source. They are welcome under the GPL, but:

- **Forks and modified versions must change the name and branding** (program
  name, service name `AuraSplitTR`, install folder, window/console titles,
  release titles) so users cannot confuse them with official builds.
- Do not describe a third-party build as "official" or imply endorsement by
  the AURA Split TR maintainers.
- Keep the copyright notices, LICENSE, NOTICE and THIRD_PARTY_LICENSES.md, and
  provide the corresponding source as required by the GPL.
- Factual statements are fine, e.g. "based on AURA Split TR".

Unmodified rebuilds from an official tag that are only used to verify
reproducibility do not need renaming, as long as they are not redistributed
as official releases.
