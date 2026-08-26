# Legacy stack: Apache prefork + mod_php 7.4 (mirrors a legacy production
# shape from the 2024 bpftrace notes). PHP lives in libphp7.so, not the exe —
# the tracer resolves symbols against the module.
FROM php:7.4-apache

RUN docker-php-ext-install pdo_mysql mysqli opcache

# Route /fast, /db, ... to the front controller (mod_dir).
RUN echo "FallbackResource /index.php" > /etc/apache2/conf-enabled/zz-fallback.conf
