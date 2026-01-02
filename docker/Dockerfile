# Start from the official Ubuntu 24.04 image (Noble Numbat)
FROM ubuntu:24.04

# Define arguments passed during the build process
ARG WWWGROUP
ARG NODE_VERSION=22
ARG MYSQL_CLIENT="mysql-client"

# Set the working directory inside the container
WORKDIR /var/www/html

# Define environment variables to prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV SUPERVISOR_PHP_COMMAND="/usr/bin/php -d variables_order=EGPCS /var/www/html/artisan serve --host=0.0.0.0 --port=80"
ENV SUPERVISOR_PHP_USER="sail"

# Synchronize container time with UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# FIX: Gebruik Leaseweb Mirror (NL) - Deze is zeer stabiel voor ARM64/Apple Silicon
RUN sed -i 's|http://ports.ubuntu.com/ubuntu-ports|http://mirror.leaseweb.com/ubuntu-ports|g' /etc/apt/sources.list.d/ubuntu.sources

# Optimization: Tweak APT settings
RUN echo "Acquire::http::Pipeline-Depth 0;" > /etc/apt/apt.conf.d/99custom && \
    echo "Acquire::http::No-Cache true;" >> /etc/apt/apt.conf.d/99custom && \
    echo "Acquire::BrokenProxy    true;" >> /etc/apt/apt.conf.d/99custom

# Step 1: Install core system utilities
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       gnupg gosu curl ca-certificates zip unzip git supervisor sqlite3 \
       libcap2-bin libpng-dev python3 dnsutils librsvg2-bin fswatch ffmpeg nano netcat-openbsd \
       autoconf pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Step 2: Install PHP, Node and Composer
RUN curl -sS 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xb8dc7e53946656efbce4c1dd71daeaab4ad4cab6' | gpg --dearmor | tee /etc/apt/keyrings/ppa_ondrej_php.gpg > /dev/null \
    && echo "deb [signed-by=/etc/apt/keyrings/ppa_ondrej_php.gpg] https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble main" > /etc/apt/sources.list.d/ppa_ondrej_php.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       libgd3 php8.4-cli php8.4-dev php8.4-mysql php8.4-mbstring php8.4-xml php8.4-zip php8.4-bcmath php8.4-curl php8.4-gd php8.4-intl php8.4-readline \
    && curl -sLS https://getcomposer.org/installer | php -- --install-dir=/usr/bin/ --filename=composer \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_VERSION.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y nodejs \
    && npm install -g pnpm \
    && apt-get install -y $MYSQL_CLIENT \
    && apt-get -y autoremove && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Enable 'setcap'
RUN setcap "cap_net_bind_service=+ep" /usr/bin/php8.4

RUN userdel -r ubuntu || true
RUN groupdel ubuntu || true

# Create the 'sail' user
RUN groupadd --force -g $WWWGROUP sail \
    && useradd -ms /bin/bash --no-user-group -g $WWWGROUP -u 1337 sail

# Copy configuration files
COPY start-container /usr/local/bin/start-container
COPY php.ini /etc/php/8.4/cli/conf.d/99-sail.ini
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN chmod +x /usr/local/bin/start-container

# Expose ports
EXPOSE 80/tcp
EXPOSE 5173/tcp

# Start
ENTRYPOINT ["start-container"]
