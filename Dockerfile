FROM golang:latest as builder

ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target="/root/.cache/go-build" CGO_ENABLED=1 go install -tags extended github.com/gohugoio/hugo@v0.150.0


WORKDIR /app
COPY . .

RUN hugo --gc --minify --environment production

FROM node:latest as pagefind

WORKDIR /app
COPY --from=builder /app/public /app/public
RUN npx pagefind --site /app/public/


FROM httpd:latest

COPY --from=pagefind /app/public /usr/local/apache2/htdocs/
RUN chown -R www-data:www-data /usr/local/apache2/htdocs/
