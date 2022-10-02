build:
    pip install .[dev]

docker:
    docker-compose build

run:
    docker-compose up --build -d
