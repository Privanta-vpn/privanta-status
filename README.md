# Independent public status delivery

This source is mirrored to the public `Privanta-vpn/privanta-status` repository
and deployed by GitHub Pages. The UI reads the freshest valid report from the
independent `stg-mon-1` origin, generated every five minutes, then falls back to
the latest GitHub workflow report. It has no production secret, customer
credential, device data, traffic data or private endpoint. Both sources fail
closed to `unknown` after 15 minutes, and Prometheus alerts on a missing or
stale origin report or an unavailable public page.

GitHub's scheduled workflow remains an off-provider fallback and is
best-effort; it is not the primary freshness mechanism.

The probe verifies only public, bounded facts. Authenticated VPN payload remains
an independent private monitoring gate and is explicitly not inferred here.
