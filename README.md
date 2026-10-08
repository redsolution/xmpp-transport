# Xabber XMPP Transport

A provider-neutral framework for connecting personal messengers to XMPP.
Telegram and MAX are the first planned backend adapters.

The project currently contains the foundation layer: provider-neutral domain
objects, commands, events, focused ports, a backend registry, configuration,
and lifecycle supervision.

## Development

```bash
python3 -m unittest discover -s tests
python3 -m xmpp_transport.runtime.app --help
```

Create a complete MAX and Telegram configuration with newly generated secrets:

```bash
python3 -m xmpp_transport.runtime.create_config \
  --telegram-api-id 123456 \
  --telegram-api-hash replace-with-telegram-api-hash
```

Both Telegram API arguments are optional. When omitted, the command leaves
`api_id` and `api_hash` empty for manual configuration later.

The command creates `transports.ini` with mode `0600`. It refuses to overwrite
an existing file unless `--force` is passed. Use `--database-dsn`,
`--server-domain`, `--component-host`, or `--output` to override defaults.

Backend adapters are discovered from the `xabber_transport.backends` Python
entry-point group. Validate a backend directly from the source checkout without
opening connections:

```bash
python3 -m xmpp_transport.runtime.app \
  --config transports.ini \
  --backend telegram \
  --check-config
```

## Daemon and systemd

The daemon lifecycle follows `xmpp-transport-max`. Each backend has its own PID
file and runs as an isolated process:

```bash
python3 -m xmpp_transport.runtime.app --config transports.ini --backend max --daemon
python3 -m xmpp_transport.runtime.app --config transports.ini --backend max --status
python3 -m xmpp_transport.runtime.app --config transports.ini --backend max --stop
```

Without `--pid-file`, PID files are stored as
`run/xabber_transport_<backend>.pid`. Override the location when integrating
with a service manager.

The systemd template can run MAX and Telegram simultaneously. Review `User`,
`Group`, `WorkingDirectory`, `ExecStart`, and `ReadWritePaths` before installing
it. Keep production secrets outside the source checkout:

```bash
sudo install -d -m 0750 -o root -g xabber-transport /etc/xabber-transport
sudo install -m 0640 -o root -g xabber-transport transports.ini /etc/xabber-transport/transports.ini
sudo cp deploy/systemd/xabber-transport@.service.example /etc/systemd/system/xabber-transport@.service
sudo systemctl daemon-reload
sudo systemctl enable --now xabber-transport@max xabber-transport@telegram
sudo systemctl status xabber-transport@max xabber-transport@telegram
```

## Local smoke backend

The built-in `fake` backend echoes an outbound direct message back through the
normal backend event, deduplication, and XMPP delivery path. Copy
`transports.example.ini`, set the two referenced environment variables, and
create an active fake binding with an encrypted non-empty credential payload.

Generate a Fernet key once and store it in the configured secret manager:

```bash
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Then validate the local wiring without opening PostgreSQL, HTTP, or XMPP:

```bash
python3 -m xmpp_transport.runtime.app \
  --config transports.ini \
  --backend fake \
  --check-config
```

Runtime integrations and their external dependencies will be introduced in
later phases rather than leaking them into the domain package.
