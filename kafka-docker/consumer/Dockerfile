# Set python version
ARG BASE_CONTAINER=python:3.8

# Set the base image 
FROM --platform=linux/amd64 $BASE_CONTAINER

# Adds metadata to image.
LABEL maintainer="iplo"

# dont write pyc files
ENV PYTHONDONTWRITEBYTECODE 1
# dont buffer to stdout/stderr
ENV PYTHONUNBUFFERED 1

# Sets the user name to use when running the image.
USER root
RUN apt update && \
    apt install --no-install-recommends -y build-essential gcc && \
    apt clean && rm -rf /var/lib/apt/lists/*

# Make a directory for app
WORKDIR /consumer

# Install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt
# RUN pip install --no-cache-dir --user -r /req.txt

# Copy source code
COPY ./app ./app

# Run the application
CMD ["python", "-m", "app"]
