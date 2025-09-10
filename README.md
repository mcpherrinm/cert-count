# Mozilla's CA data

Mozilla has a `cert.validation_success_by_ca_2` metric:

[Glam Link](https://glam.telemetry.mozilla.org/fog/probe/cert_validation_success_by_ca_2)

Using that UI is impossible to understand what is going on.

This tool takes a JSON export from Glam and turns it into a CSV.
It uses a copy of firefox/security/manager/tools/KnownRootHashes.txt to get CA Names.

See graph in [CA.svg](CA.svg)
