#!/bin/sh
# Creates the screenshots bucket with no anonymous access (idempotent).
set -eu
mc alias set local http://minio:9000 "$S3_ACCESS_KEY_ID" "$S3_SECRET_ACCESS_KEY" >/dev/null
mc mb --ignore-existing "local/$S3_BUCKET"
mc anonymous set none "local/$S3_BUCKET"
echo "Bucket $S3_BUCKET ready (private)"
