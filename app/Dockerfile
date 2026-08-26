# Demo PHP app: php-fpm 8.3 with mysqlnd-backed drivers.
# The tracer resolves symbols against this exact binary, so pin the minor.
FROM php:8.3-fpm

RUN docker-php-ext-install pdo_mysql mysqli opcache

COPY fpm-apm.conf /usr/local/etc/php-fpm.d/zz-apm.conf

# Bake the source so the image is self-contained for k8s (in docker-compose
# the ./app/src bind-mount overlays this, so local dev is unaffected).
COPY src/ /var/www/html/
