# Community sponsor timings

`sponsor-fetch` produces a local timing file on explicit request. It does not
read browser state, install an extension, or change playback. The optional
page-controls companion is still under qualification and is not part of this
release. Community suggestions need a person's review of the audio and video;
a matching duration alone cannot prove that a suggestion describes this edit.

```sh
egress-guard sponsor-fetch --duration SECONDS --output ./new-timings.json -- VIDEO_ID
```

Replace `VIDEO_ID` with the exact eleven-character YouTube ID and `SECONDS`
with the current video's duration. `--include-selfpromo` also requests the
separate self-promotion category. The `--` separator also supports valid IDs
beginning with a dash. By default only sponsor intervals with the
`skip` action are requested. The command refuses an existing output path,
including links. On supported filesystems it publishes a completed new file
atomically; POSIX output files have mode 0600. It creates no parent directories.

Without `--output`, successful JSON goes to stdout. Shell redirection can
truncate a destination before this command starts: use `--output` when
preserving existing files matters. Video IDs on a command line can also appear
in shell history and local process listings. Avoid using private or sensitive
video identifiers without considering that exposure.

## Request and validation

The command computes SHA-256 over the case-sensitive ID and sends only the
first four lowercase hexadecimal characters to SponsorBlock's HTTPS endpoint,
along with category, action and service filters. It sends no cookies,
authorization, page URLs or browser history. It does not submit segments, ping
views, retry in the background, or retain a lookup cache. The request connects
directly, bypassing HTTP proxy environment settings; operating-system DNS and
VPN routing still apply. TLS uses the platform trust configuration.

This reduces the identifier sent to the service, but is not anonymity: a prefix
may identify a single video, the provider sees the connection, and its privacy
policy describes IP-based counting and some connection logging. The exported
file intentionally contains the full video ID.

Response bodies are limited to 2 MiB. Duplicate fields, non-finite numbers,
excessive structure/nesting, redirects, ambiguous framing, wrong media types
and truncated replies are refused. A 20-second response budget starts after
the connection and TLS handshake; the socket timeout is ten seconds. DNS and
connection establishment do not have a guaranteed overall wall-clock limit.

Returned groups must match the requested prefix; selection of the exact video
happens locally. An empty bucket or an absent exact ID means no suggestions
were returned, not that the video has no sponsorship. Each selected suggestion
must have a positive provider duration within one second of the independently
supplied current duration. Unknown/stale duration, unrequested categories,
invalid endpoints, overlapping intervals, more than 100 intervals, or intervals
covering at least 80% of the video cause refusal rather than guessed repairs.

## File format and attribution

The JSON contains `videoId`, `duration`, and sorted `segments`. Each segment
contains `start`, `end`, `category`, and `actionType`. The `source` object retains
SponsorBlock's provider URL, CC BY-NC-SA 4.0 license and link, retrieval time,
and the format changes made. UUIDs, votes, descriptions and other video groups
are not exported. Keep the attribution and license information when sharing
files. Community timing data has separate noncommercial/share-alike terms;
this project's MIT code license does not relicense it.

- [Current server prefix route](https://github.com/ajayyy/SponsorBlockServer/blob/671b05f0a646db930e9e7ba6d75225adcb62b2e4/src/routes/getSkipSegmentsByHash.ts)
- [Current server segment fields](https://github.com/ajayyy/SponsorBlockServer/blob/671b05f0a646db930e9e7ba6d75225adcb62b2e4/src/routes/getSkipSegments.ts)
- [Data/API license](https://github.com/ajayyy/SponsorBlock/wiki/Database-and-API-License)
- [Privacy policy](https://gist.github.com/ajayyy/aa9f8ded2b573d4f73a3ffa0ef74f796)
- [Service terms](https://gist.github.com/ajayyy/9e8100f069348e0bc062641f34d6af12)
