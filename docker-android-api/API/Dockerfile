FROM python:3.10-bullseye

ENV PYTHONUNBUFFERED=1

WORKDIR /API

COPY requirements.txt .

RUN ["pip", "install", "-r", "requirements.txt"]

# COPY . .