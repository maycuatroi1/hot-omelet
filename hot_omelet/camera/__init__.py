"""
IP camera / DVR / NVR assessment package.

Authorized LAN camera security reviews only. Discovery + read-only
fingerprinting + a small known-default credential check + known-CVE
detection. No config writes, no brute force, no firmware operations.
"""

from hot_omelet.camera.scan import camera_scan_command

__all__ = ["camera_scan_command"]
