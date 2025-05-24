build:
	pip install --no-cache-dir --compile .
	pip install --no-cache-dir --compile .[server]

dev: 
	pip install --no-cache-dir --compile .[dev]

docker:
	docker compose build

podman:
	podman compose build

run:
	docker compose up --build -d
