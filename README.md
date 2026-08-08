# Independent public status delivery

This source is mirrored to the public `Privanta-vpn/privanta-status` repository
and deployed by GitHub Pages every five minutes. It has no production secret,
customer credential, device data, traffic data or private endpoint.

The probe verifies only public, bounded facts. Authenticated VPN payload remains
an independent private monitoring gate and is explicitly not inferred here.
