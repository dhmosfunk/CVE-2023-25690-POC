FROM php:7.4-apache

COPY src/. /var/www/html/

RUN sed -i 's/80/8080/g' /etc/apache2/sites-available/000-default.conf /etc/apache2/ports.conf

RUN apt-get update && apt-get install -y dnsutils

CMD ["apache2-foreground"]
