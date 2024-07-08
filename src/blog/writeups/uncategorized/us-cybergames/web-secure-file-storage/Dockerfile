FROM python:3-alpine

# Install packages
RUN apk add --update --no-cache supervisor git

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install dependencies
RUN pip install gunicorn Flask pyjwt flask_sqlalchemy pycryptodome pymysql

# Copy flag
COPY flag.txt /flag.txt

# Protect flag
RUN chmod 444 /flag.txt

# add user
RUN adduser -D -u 1000 -g 1000 -s /usr/sbin/nologin www

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .

# Give ownership of folder to www user
RUN chown -R www:www /app

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 80

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# Run supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]