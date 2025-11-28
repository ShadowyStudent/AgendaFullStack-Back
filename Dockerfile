FROM php:8.2-apache

RUN docker-php-ext-install mysqli pdo pdo_mysql

COPY . /var/www/html/

EXPOSE 10000

CMD ["php", "-S", "0.0.0.0:${PORT}", "-t", "/var/www/html"]