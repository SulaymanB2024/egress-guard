# Public Suffix List

The complete ICANN and PRIVATE sections are packaged offline in `public_suffix_list.dat` and the generated `../core/psl-data.js` module. This source is maintained by the Public Suffix List project and contributors.

- Canonical source: https://publicsuffix.org/list/public_suffix_list.dat
- Format and update instructions: https://publicsuffix.org/list/
- License: Mozilla Public License 2.0 (SPDX `MPL-2.0`), https://mozilla.org/MPL/2.0/
- Snapshot version, upstream commit, and SHA-256: embedded in `psl-data.js` metadata; the source also includes its version and commit.

To update, download the canonical source, review its provenance and diff, and run `node scripts/update-psl.mjs`. The generator has no network access and normalizes IDN entries with Node's WHATWG URL implementation. Commit both source and generated module. Never silently refresh a running browser's scope definitions: shipping a new PSL is a reviewed extension update, and stored scopes are revalidated on load.

The data is provided under MPL-2.0. All original notices and contributor attribution are preserved in the source file. The extension does not transmit hostnames to the PSL service.
