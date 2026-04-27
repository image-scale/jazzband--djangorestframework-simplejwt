#!/bin/bash
set -eo pipefail

export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
export CI=true

cd /workspace/djangorestframework-simplejwt

pytest tests/ --tb=short --no-cov -p no:cacheprovider

