# hap-model

The HomeKit accessory attribute database for [`hap-rust`](../../README.md)
(Milestone 6). Transport-agnostic: it parses and serializes JSON and never
touches the network.

## What it does

- Parse `GET /accessories` JSON into a typed `Accessory → Service →
  Characteristic` tree (`parse_accessories`).
- Build and parse `/characteristics` read / write / subscribe requests
  (`build_read_request`, `parse_read_response`, `build_write_request`,
  `build_subscribe_request`).
- Model characteristic formats (`CharFormat`), decoded values (`CharValue`),
  permissions (`Perms`), and value constraints.
- Code-generated `ServiceType` / `CharacteristicType` tables with short-UUID
  expansion and default formats.
- An optional `AccessoryDatabase<E: RequestExecutor>` for typed access given a
  caller-supplied request executor (the controller wires in a secure session).

## Codegen

The HAP type tables are generated from `xtask/model/hap-types.json`:

```
cargo xtask codegen-hap-types
```

This rewrites `src/generated.rs`, which is committed.

## Status

Pre-1.0. See the workspace roadmap.
