version: "3.9"
services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile
    working_dir: /app/backend
    command: python main.py
    volumes:
      - ./backend:/app/backend
    ports:
      - "9000:9000"
    environment:
      - PYTHONUNBUFFERED=1
