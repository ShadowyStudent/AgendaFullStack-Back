FROM php:8.2-apache

RUN apt-get update && apt-get install -y \
    default-mysql-client \
    default-libmysqlclient-dev \
    && docker-php-ext-install pdo pdo_mysql

COPY . /var/www/html/

RUN a2enmod rewrite headers

RUN chown -R www-data:www-data /var/www/html/uploads \
    && chmod -R 755 /var/www/html/uploads