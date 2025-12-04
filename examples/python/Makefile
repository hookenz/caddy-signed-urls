PYTHON := python3
VENV := venv
ACTIVATE := . $(VENV)/bin/activate

.PHONY: all venv install run clean

all: run

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(ACTIVATE) && pip install --upgrade pip && pip install requests

run: install
	$(ACTIVATE) && python main.py

clean:
	rm -rf $(VENV)
