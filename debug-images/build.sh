#!/bin/bash
set -euo pipefail
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

docker build -t jnsgruk/dashboard:debug -f "${DIR}/Dockerfile.dashboard" "${DIR}"
docker build -t jnsgruk/scraper:debug -f "${DIR}/Dockerfile.scraper" "${DIR}"

docker save jnsgruk/dashboard:debug | microk8s.ctr image import -
docker save jnsgruk/scraper:debug | microk8s.ctr image import -