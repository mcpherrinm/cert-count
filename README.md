# Mozilla's CA data

Mozilla has a `cert.validation_success_by_ca` metric:

[Glam Link](https://glam.telemetry.mozilla.org/fog/probe/cert_validation_success_by_ca/explore?aggregationLevel=version&app_id=release&normalizationType=non_normalized&visiblePercentiles=%5B%5D)

Using that UI is impossible to understand what is going on.

This tool takes a JSON export from Glam and turns it into a CSV.
It uses a copy of security/manager/tools/RootHashes.json to get CA Names.
I removed the JSON comments at the head of that file manually to make it JSON.

See graph in [CA.svg](CA.svg)
