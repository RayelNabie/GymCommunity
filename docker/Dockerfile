# -----------------------------------------------------------------------------
# Base Image & Arguments
# -----------------------------------------------------------------------------

FROM ubuntu:24.04

ARG WWWGROUP
ARG NODE_VERSION=22
ARG MYSQL_CLIENT="mysql-client"

WORKDIR /var/www/html

# -----------------------------------------------------------------------------
# Environment Configuration
# -----------------------------------------------------------------------------
# DEBIAN_FRONTEND: Suppress interactive prompts during build.
# TZ:              Force UTC time to prevent timezone-related data offsets.
# COMMAND:         Configures the PHP-cli server command.
#                  - variables_order=EGPCS: Ensures $_ENV is populated (12-Factor App).
#                  - expose_php=Off: Security hardening (hides PHP version headers).

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV SUPERVISOR_PHP_COMMAND="/usr/bin/php -d variables_order=EGPCS /var/www/html/artisan octane:start --server=frankenphp --host=0.0.0.0 --port=80 --admin-port=2019"
ENV SUPERVISOR_PHP_USER="sail"

# -----------------------------------------------------------------------------
# Infrastructure & Mirrors
# -----------------------------------------------------------------------------

# Timezone: Sync container time with UTC.
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Mirror Selection: Switch to Leaseweb (HTTPS) to resolve frequent synchronization
# and hash-mismatch errors observed with default 'ports.ubuntu.com' on ARM64.
RUN sed -i 's|http://ports.ubuntu.com/ubuntu-ports|http://mirror.leaseweb.com/ubuntu-ports|g' /etc/apt/sources.list.d/ubuntu.sources

# APT Optimization: Disable HTTP pipelining and caching to improve build stability.
RUN echo "Acquire::http::Pipeline-Depth 0;" > /etc/apt/apt.conf.d/99custom && \
    echo "Acquire::http::No-Cache true;" >> /etc/apt/apt.conf.d/99custom && \
    echo "Acquire::BrokenProxy    true;" >> /etc/apt/apt.conf.d/99custom

# -----------------------------------------------------------------------------
# Core Dependencies
# -----------------------------------------------------------------------------
# Install essential system utilities.
# - gosu: Used for stepping down from root to 'sail' user.
# - setcap/libcap2-bin: Required to allow PHP to bind to port 80 without root.

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates\
       gnupg gosu curl zip unzip git supervisor sqlite3 \
       libcap2-bin libpng-dev python3 dnsutils librsvg2-bin fswatch ffmpeg nano netcat-openbsd \
       autoconf pkg-config \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# Application Stack (PHP & Node)
# -----------------------------------------------------------------------------
# 1. Add Ondrej PPA for PHP 8.4 (Official Ubuntu repos often lag behind).
# 2. Add NodeSource for Node.js 22.
# 3. Install PHP extensions required by Laravel.
# 4. Install Global Composer & PNPM.
# 5. Cleanup: 'autoremove' reduces final image size.

RUN curl -sS 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xb8dc7e53946656efbce4c1dd71daeaab4ad4cab6' | gpg --dearmor | tee /etc/apt/keyrings/ppa_ondrej_php.gpg > /dev/null \
    && echo "deb [signed-by=/etc/apt/keyrings/ppa_ondrej_php.gpg] https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble main" > /etc/apt/sources.list.d/ppa_ondrej_php.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       libgd3 php8.4-cli php8.4-dev php8.4-mysql php8.4-mbstring php8.4-xml php8.4-zip php8.4-bcmath php8.4-curl php8.4-gd php8.4-intl php8.4-readline php8.4-opcache \
    && curl -sLS https://getcomposer.org/installer | php -- --install-dir=/usr/bin/ --filename=composer \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_VERSION.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y nodejs \
    && npm install -g pnpm \
    && apt-get install -y $MYSQL_CLIENT \
    && apt-get -y autoremove && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# -----------------------------------------------------------------------------
# Security & Permissions
# -----------------------------------------------------------------------------
# Networking: Allow the PHP binary to bind to privileged ports (80)
# without running the process as the 'root' user.

RUN setcap "cap_net_bind_service=+ep" /usr/bin/php8.4

# User Management:
# 1. Remove default 'ubuntu' user (UID 1000) to prevent conflicts.
# 2. Create 'sail' user matching the host UID (passed via build args).
#    This ensures files created in volumes are editable on the host machine.

RUN userdel -r ubuntu || true && groupdel ubuntu || true \
    && groupadd --force -g $WWWGROUP sail \
    && useradd -ms /bin/bash --no-user-group -g $WWWGROUP -u 1337 sail

# -----------------------------------------------------------------------------
# Entrypoint & Config
# -----------------------------------------------------------------------------

COPY start-container /usr/local/bin/start-container
COPY php.ini /etc/php/8.4/cli/conf.d/99-sail.ini
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN chmod +x /usr/local/bin/start-container

EXPOSE 80/tcp
EXPOSE 5173/tcp

ENTRYPOINT ["start-container"]
