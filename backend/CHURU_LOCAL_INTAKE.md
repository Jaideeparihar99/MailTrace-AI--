# Churu regional intake (local development only)

The `CHURU-SOC` queue is an explicitly local MailTrace intake placeholder for
cases whose **reported** location is Taranagar/Churu, Rajasthan. It is not a
verified public-sector SOC queue and it does not dispatch email, webhooks, or
alerts to an external department.

## Provision the queue

From the `backend` folder, preview the exact configuration first:

```console
python scripts/configure_churu_local_intake.py
```

Apply it only to the local development database:

```console
python scripts/configure_churu_local_intake.py --apply
```

The bootstrap is idempotent, rejects non-`local` tenants, and refuses to run
when the application is in production mode. It creates only the queue; it does
not create fake analysts, map a user's identity/location, or claim external
notification succeeded. Regional assignments remain queued until a real,
authorized analyst roster and verified routing inputs are configured.

Runtime case rows, evidence files, email contents, and SQLite databases are
intentionally ignored by Git and should not be committed. A case such as
`CASE-B31F817E3A` must be reviewed through the running instance's case API/UI;
this repository bootstrap does not embed or distribute case data.
