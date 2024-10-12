# ClamAV Service

This service uses the ClamAV antivirus engine to scan files for viruses. It leverages the daemon mode to keep db
definitions in memory and avoid reloading them for each scan.

The Freshclam as well as custom databases are supported, both as AL-native update sources.

## Configuring

To configure ClamAV, you can edit the service parameters: any config key not starting
with `_` will be added to the `clamd.conf` file.

To modify the Freshclam, go to the update sources configuration. The `freshclam` source
is reserved for updates using the Freshclam utility, and the headers are treated as
`freshclam.conf` options.

To add other sources, just add them as a new source with a correct url. Remember that
the files have to have the right extension and their names cannot repeat. You can read
more in the [ClamAV documentation](https://github.com/Cisco-Talos/clamav-documentation/blob/main/src/manual/Signatures.md#signature-databases)