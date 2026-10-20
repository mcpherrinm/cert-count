# Mozilla's CA data

Mozilla has a `cert.validation_success_by_ca_2` metric:

[Glam Link](https://glam.telemetry.mozilla.org/fog/probe/cert_validation_success_by_ca_2)

Using that UI is impossible to understand what is going on.

This tool takes a JSON response from the Glam API and turns it into a CSV:

```
curl -X POST https://glam.telemetry.mozilla.org/api/v1/data/ \
  -H 'Content-Type: application/json' \
  -d '{"query":{"app_id":"nightly","product":"fog","probe":"cert_validation_success_by_ca_2","os":"*","aggregationLevel":"build_id","ping_type":"*"}}' \
  -o cert.validation_success_by_ca_2.json
```

It uses a copy of firefox/security/manager/tools/KnownRootHashes.txt to get CA Names.

See graph in [CA.svg](CA.svg)
