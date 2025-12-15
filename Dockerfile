FROM node:25-bookworm-slim

RUN apt-get update && \
    apt-get install -y \
    curl binutils git