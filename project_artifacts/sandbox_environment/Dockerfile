# Lightweight and stable Python image based on Debian Slim.
FROM python:3.13-slim

# Prevents the creation of bytecode files.
ENV PYTHONDONTWRITEBYTECODE=1
# Forces stdout/stderr to be flushed immediately.
ENV PYTHONUNBUFFERED=1
# Provides easier crash diagnostics.
ENV PYTHONFAULTHANDLER=1

# Updates package indexes and installs required system utilities:
# Shell environment, standard command-line tools, Python packages ...
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    coreutils \
    file \
    binutils \
    xxd \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Updates pip to the lates version available.
RUN pip install --no-cache-dir --upgrade pip

# Installs Python packages required for cryptography.
RUN pip install --no-cache-dir \
    cryptography \
    pycryptodome \
    pyjwt

# Installs Python packages required for malware analysis.
RUN pip install --no-cache-dir \
    pefile \
    yara-python \
    construct \
    puremagic

# Sets up the working directory.
WORKDIR /sandbox

# Creates a non-root user and grants ownership of the folder.
RUN useradd -m -s /bin/bash sandboxuser && \
    chown -R sandboxuser:sandboxuser /sandbox

# Switches to the new user.
USER sandboxuser

# Overrides HOME to point to the sandbox directory.
ENV HOME=/sandbox

# Keeps the container alive indefinitely.
CMD ["tail", "-f", "/dev/null"]