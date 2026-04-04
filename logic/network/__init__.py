"""
PACKAGE: logic.network
DESCRIPTION: Suite completa per operazioni di Cyber Reconnaissance, Scanning e Web Intelligence.
COMPONENTS:
    - Port Scanning (Industrial / Ghost)
    - Web Recon (Headers / Robots / Verbs)
    - SSL Inspection (TLS Details / SANs)
    - Resource Discovery (Directory Busting)
"""

from .port_scanner import scansione_porte, ottieni_ip
from .ghost_scanner import scansione_porte_ghost
from .constants import RISCHIO_PORTE, TOP_PORTS
from .http_recon import analizza_headers, analizza_robots, analizza_verbi_http
from .ssl_inspector import get_ssl_details
from .directory_buster import cerca_directory_nascoste
