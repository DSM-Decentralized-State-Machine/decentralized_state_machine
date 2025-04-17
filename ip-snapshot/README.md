# IP Snapshot Module

A module for the DSM (Decentralized State Machine) system to collect, store, and analyze IP addresses with geographic distribution.

## Recent Fixes

The following critical issues were fixed:

1. **GeoIP Lookup Failures**
   - Implemented fault tolerance in the GeoIP service
   - Added default geo information for addresses not found in the database
   - Silently recovered from errors instead of failing lookup operations

2. **Snapshot Storage Issues**
   - Fixed the snapshot store implementation to properly store collected IP entries
   - Implemented in-memory caching for efficient collection
   - Enhanced metadata tracking and country statistics generation

3. **Export Processing**
   - Fixed the export mechanism to handle both empty and populated snapshots
   - Added comprehensive error handling for export operations
   - Improved JSON and CSV export with more detailed information

## Usage

Run the scanner with:

```bash
./run_simple_scanner.sh
```

Export data with:

```bash
./target/release/ip-snapshot export --data ./data --format json --output ./data/ip_snapshot_export.json
```

Or use the combined fix script:

```bash
./ip-snapshot-fixes.sh
```

## Configuration

The scanner behavior can be configured in `config.json`:

- GeoIP database path
- Regional scanning options
- Concurrency levels
- Scan ranges

## Dependencies

- MaxMind GeoLite2 City database (`GeoLite2-City.mmdb`)
- Tokio for async processing
- Serde for serialization

## License

See the DSM project license for details.
