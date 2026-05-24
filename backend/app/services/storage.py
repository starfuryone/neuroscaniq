"""S3 / MinIO object storage."""

from __future__ import annotations

from typing import BinaryIO

import boto3
from botocore.client import Config

from app.config import settings


def _client():
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint,
        region_name=settings.s3_region,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def put_object(bucket: str, key: str, data: BinaryIO | bytes, *, content_type: str = "application/octet-stream") -> str:
    body = data.read() if hasattr(data, "read") else data  # type: ignore[union-attr]
    _client().put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)
    return f"{settings.s3_public_url.rstrip('/')}/{bucket}/{key}"


def presigned_url(bucket: str, key: str, *, expires: int = 3600) -> str:
    return _client().generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expires,
    )
