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

The report uses schema version 2. Its VPN network component is generated from
fresh synthetic relay probes delivered by every commercial IN through a
TLS-protected, source-IP-allowlisted Pushgateway endpoint. Each credential is
bound to one exact telemetry job. The public snapshot contains only aggregate
expected, fresh, available and redundant path counts; it contains no node ID,
address, customer session, destination or traffic content.

Control API, bootstrap and application-update components still verify only
public bounded facts. The VPN network component is never inferred from those
HTTP checks. An invalid, stale, unauthenticated or inconsistent Data Plane
snapshot fails closed to an outage state.
