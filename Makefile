build:
	xcaddy build --with github.com/hookenz/caddy-signedurls=.

run:
	./caddy run --config examples/caddy/Caddyfile

test:
	go test ./...
