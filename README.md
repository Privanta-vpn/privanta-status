# Independent public status delivery

This source is mirrored to the public `Privanta-vpn/privanta-status` repository
and deployed by GitHub Pages on a five-minute, off-hour-boundary schedule. It
has no production secret, customer credential, device data, traffic data or
private endpoint. GitHub scheduling is best-effort: the page fails closed to
`unknown` after 15 minutes, and the independent Privanta monitor alerts on a
missing or stale public report.

The probe verifies only public, bounded facts. Authenticated VPN payload remains
an independent private monitoring gate and is explicitly not inferred here.
