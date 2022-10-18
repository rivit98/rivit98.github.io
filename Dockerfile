FROM klakegg/hugo as builder

WORKDIR /app
COPY . .

RUN hugo --gc --minify


FROM httpd:2.4-alpine

COPY --from=builder /app/public /usr/local/apache2/htdocs/
RUN chown -R www-data:www-data /usr/local/apache2/htdocs/
