# YARA rule sources

## Built in

| File | Source | License |
|---|---|---|
| `linux.yar` | Written for Wachposten | GPL-3.0-or-later |

## Adding more rules

Put `.yar` or `.yara` files in a folder and list it in `~/.config/wachposten/config.toml`:

```toml
[yara]
extra_rule_dirs = ["/home/you/yara-rules"]
```

Every file becomes its own namespace. Files that YARA-X cannot compile are reported by
`wachposten rules` and skipped; the rest keep working.

Check the license before you use a public set. Some well-known sets allow only non-commercial
use. Sets worth a look, by license:

| Set | License | Notes |
|---|---|---|
| [ReversingLabs yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | MIT | Mostly Windows malware |
| [YARA Forge](https://yarahq.github.io/) | Per rule, filterable | Curated packages from many sources |
| [signature-base (Neo23x0)](https://github.com/Neo23x0/signature-base) | Detection Rule License 1.1 | Attribution required |
| [Elastic protections-artifacts](https://github.com/elastic/protections-artifacts) | Elastic License 2.0 | Good Linux coverage, restrictive license |

Wachposten does not ship any of these, so their licenses do not apply to Wachposten itself.
