install:
	pip install -r requirements.txt

generate:
	python scripts/generate_logs.py

parse:
	python src/cli.py parse logs/access.log

summary:
	python src/cli.py summary

anomalies:
	python src/cli.py anomalies

watch:
	python src/cli.py watch logs/access.log

api:
	python src/api.py

streamlit:
	streamlit run src/app.py

test:
	pytest tests/ -v

lint:
	flake8 src/ tests/
	isort --check-only src/ tests/

format:
	black src/ tests/ scripts/
	isort src/ tests/ scripts/

docker:
	docker-compose -f docker/docker-compose.yml up --build

clean:
	python src/cli.py resetdb
	rm -f logs/*.log

.PHONY: install generate parse summary anomalies watch api streamlit test lint format docker clean
