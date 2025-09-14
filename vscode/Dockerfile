# Base image
FROM ubuntu:22.04

# Set environment variable for code-server version
ENV VERSION=4.9.1

# Avoid user interaction during installkk
ENV DEBIAN_FRONTEND=noninteractive

# Update and install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    sudo \
    gnupg \
    ca-certificates \
    libasound2 \
    libnss3 \
    libxss1 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxrandr2 \
    libgbm1 \
    libxdamage1 \
    libpango-1.0-0 \
    libatk1.0-0 \
    libatk1.0-data \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Create user 'ubuntu'
RUN useradd -m -s /bin/bash ubuntu && echo "ubuntu ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Switch to a temp directory
WORKDIR /tmp

# Download and install code-server
RUN curl -fOL https://github.com/coder/code-server/releases/download/v${VERSION}/code-server_${VERSION}_amd64.deb \
    && dpkg -i code-server_${VERSION}_amd64.deb \
    && rm code-server_${VERSION}_amd64.deb

# Create config directories and files
RUN mkdir -p /opt/code-server/User && \
    echo 'bind-addr: 0.0.0.0:8443\nauth: none\ncert: false' > /opt/code-server/codeserver.yml && \
    chown -R ubuntu:ubuntu /opt/code-server

# Add coder.json and settings.json config files properly
RUN mkdir -p /opt/code-server/User && \
    printf '%s\n' \
    '{' \
    '  "query": {' \
    '    "folder": "/home/ubuntu/"' \
    '  },' \
    '  "update": {' \
    '    "checked": 1671967887901,' \
    '    "version": "4.9.1"' \
    '  }' \
    '}' > /opt/code-server/coder.json && \
    printf '%s\n' \
    '{' \
    '  "workbench.colorTheme": "Default Dark+",' \
    '  "workbench.startupEditor": "none",' \
    '  "files.exclude": {' \
    '    "**/.**": true' \
    '  },' \
    '  "window.menuBarVisibility": "visible",' \
    '  "workbench.activityBar.visible": visible,' \
    '  "workbench.statusBar.visible": visible' \
    '}' > /opt/code-server/User/settings.json && \
    chown -R ubuntu:ubuntu /opt/code-server

# Change to non-root user
USER ubuntu

# Set working directory
WORKDIR /home/ubuntu

# Expose code-server port
EXPOSE 8443

# Launch code-server with given parameters
CMD [ "code-server", "--auth", "none", "--cert", "false", "--bind-addr", "0.0.0.0:8443", "--user-data-dir", "/opt/code-server", "--disable-getting-started-override", "--disable-update-check", "--disable-workspace-trust", "--disable-file-downloads", "--config", "/opt/code-server/codeserver.yml" ]
