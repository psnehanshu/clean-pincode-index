# CleanPincode.in

A website that tracks the cleanliness of every pincode in India by crowdsourcing votes.

## Start

First, install Go. [See installation instructions](https://go.dev/doc/install).

Then install SQLC

```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

Then generate the query files running

```bash
sqlc generate
```

Procure a Postgres server, either by installing it locally or by using a hosted service like Supabase or Neon.

Then create a Google Client ID using [these steps](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid).

Then create a `.env` file using the format from `.env.example`

Then Install Air

```bash
go install github.com/air-verse/air@latest
```

Then you can start the server (with live reloading) by running

```bash
air
```

Then open [http://localhost:3000](http://localhost:3000) in your browser.