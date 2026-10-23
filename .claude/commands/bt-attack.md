---
name: bt-review
description: Bluetooth configuration review - scan, enumerate, and review nearby Bluetooth/BLE device exposure. Usage /bt-review [action]
---

# Bluetooth Configuration Review

Arguments: `$ARGUMENTS`

Review Bluetooth/BLE device exposure in the lab environment.

## Phases

### Phase 1: Discovery
1. Check Bluetooth adapter: `blueutil` (macOS) or `hcitool dev` (Linux)
2. Scan Classic + BLE devices in range
3. Collect: device name, MAC, RSSI, device class, services
4. Identify device types

### Phase 2: Enumeration
1. Enumerate services per device (SDP for Classic, GATT for BLE)
2. Fingerprint firmware versions
3. Check discoverable/connectable mode
4. Identify weak security posture

### Phase 3: Assessment
- BLE: check readable/writable characteristics without auth
- Audio: review pairing and discoverability posture
- IoT: review pairing configuration
- Version mapping to known CVEs

## Tools
- `bleak` (Python BLE, cross-platform)
- `blueutil` (macOS)
- `bettercap` (BLE scanning)
- `hcitool` / `bluetoothctl` (Linux)

## Workspace
Save results to `./reports/bluetooth/`
