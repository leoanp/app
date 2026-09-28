# .app

An open, OS-neutral app format for modern Linux: one sealed file per app,
isolated by the kernel, with nothing running beside it.

- **Specification:** [`spec/spec.md`](spec/spec.md) (CC BY 4.0)
- **Foundation list:** [`spec/foundation.toml`](spec/foundation.toml)
- **Reference runtime and packager:** this repository (Apache-2.0)

Status: early development. See [`CLAUDE.md`](CLAUDE.md) for the build order.

## Layout

| Path | Contents |
| --- | --- |
| `crates/` | All real logic, as libraries |
| `bins/app` | The `app` command (install, update, remove, list) |
| `bins/app-pack` | Packager commands (`app build`, `app convert`, …) |
| `bins/app-launcher` | Privileged, socket-activated launcher |
| `data/` | systemd, polkit, D-Bus and MIME files |
| `tests/` | Fixtures, sandbox-escape tests, VM scripts |

## Building

Requires Linux (kernel 6.12+ for runtime tests) and stable Rust.

```sh
cargo build
cargo test
```
