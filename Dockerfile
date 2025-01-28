FROM golang:1.23 AS build

COPY --from=sqlc/sqlc /workspace/sqlc /usr/bin/

WORKDIR /app
ADD . .

RUN sqlc generate
RUN go build -o tmp/app

FROM debian:stable-slim

COPY --from=build /app/tmp/app /usr/bin/

EXPOSE 3000

CMD ["app"]
