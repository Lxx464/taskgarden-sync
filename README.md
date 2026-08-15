# TaskGarden Sync

A blob store for [TaskGarden](https://todo.celexstrategy.com), so the app can
sync between your devices without Google Drive.

It holds one JSON document per pairing code and hands it back. It does not
merge, it does not validate, and with encryption switched on in the app it
cannot read what it holds — the client seals the payload before it is sent.

Two files, no dependencies. Everything the service does is in `handler.js`
(the rules) and `index.js` (a `node:http` server and a file on disk).

## Run it

You need a machine with Docker and a way to serve it over HTTPS — a reverse
proxy that already terminates TLS for something else is the usual answer. The
pairing code is a bearer token; over plain HTTP it is a token you have given
away.

```bash
git clone https://github.com/Lxx464/taskgarden-sync.git
cd taskgarden-sync

docker build -t taskgarden-sync .
docker run -d --name taskgarden-sync \
  -e SYNC_CODES="$(openssl rand -hex 24)" \
  -v taskgarden-sync-data:/data \
  --restart always \
  -p 127.0.0.1:8080:8080 \
  taskgarden-sync
```

`docker logs taskgarden-sync` confirms it started. Point your proxy at
`127.0.0.1:8080`, then open TaskGarden → Settings → Account → *Where syncing
happens*, choose **Your own server**, and enter the address plus the code you
generated above.

Print the code before you lose it — `openssl rand` does not remember it either:

```bash
docker exec taskgarden-sync printenv SYNC_CODES
```

## Configuration

| Variable | Meaning |
|---|---|
| `SYNC_CODES` | Comma-separated pairing codes. **Required** — the service refuses to start without one. Each code is its own bucket, so several people can share one instance and none can reach another's data. |
| `SYNC_ORIGINS` | Comma-separated origins allowed to call it. Defaults to `https://todo.celexstrategy.com,https://localhost`, which covers the public website and the Android app — if that is where you use TaskGarden, leave this alone. Set it only when you host your own copy of the app. |
| `SYNC_DATA` | Where the blobs go. Default `/data`. |
| `PORT` | Default `8080`. |

The origin list is deliberately not a wildcard: any page open in your browser
can send requests, and `*` would let one of them talk to this service with a
code it picked up somewhere.

## API

    GET  /snapshot   → 200 with the document, or 404 if there is none yet
    PUT  /snapshot   → 204
    Authorization: Bearer <pairing code>

`404` means "nothing stored yet", and the app responds by making this device's
data the account. `401` means the code was refused. Keeping those apart is the
reason the service exists in this shape at all: conflating them is how a wrong
code would silently overwrite someone's data.

Snapshots above 8 MB are rejected with `413`.

## Backups

```bash
docker run --rm -v taskgarden-sync-data:/data -v "$PWD:/out" alpine \
  tar czf /out/taskgarden-sync-backup.tar.gz /data
```

Whatever you back up is encrypted if the app's encryption is on — which also
means the backup is worthless without the passphrase. Keep that somewhere else.

## Tests

```bash
npm install
npm test
```

The tests cover `handler.js` alone: who is let in, what a missing snapshot
returns, which origins may call. Those are the rules worth having a test for,
and they are the reason they live away from `node:http` rather than being
verified by curling a running container.

## License

MIT — see `LICENSE`.
