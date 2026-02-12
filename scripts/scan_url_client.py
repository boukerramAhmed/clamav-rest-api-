#!/usr/bin/env python3
"""
Client script that simulates the presigned URL scan workflow:
1. Upload a file to S3 (MinIO)
2. Generate a presigned URL for the object
3. Send the presigned URL to the ClamAV API /api/v1/scan/url endpoint
4. Print the scan result
"""

import argparse
import json
import sys

import boto3
import httpx
from botocore.config import Config as BotoConfig


def main():
    parser = argparse.ArgumentParser(description="Scan a file via presigned S3 URL")
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument(
        "--api-url", default="http://localhost:8080", help="ClamAV API base URL"
    )
    parser.add_argument(
        "--s3-endpoint", default="http://localhost:9000", help="S3/MinIO endpoint"
    )
    parser.add_argument("--s3-access-key", default="minioadmin", help="S3 access key")
    parser.add_argument("--s3-secret-key", default="minioadmin", help="S3 secret key")
    parser.add_argument("--s3-bucket", default="scans", help="S3 bucket name")
    parser.add_argument(
        "--presigned-endpoint",
        default="http://minio:9000",
        help="Endpoint used in presigned URLs (Docker DNS)",
    )
    parser.add_argument(
        "--url-expiry", type=int, default=3600, help="Presigned URL expiry in seconds"
    )
    args = parser.parse_args()

    # 1. Create S3 client
    s3 = boto3.client(
        "s3",
        endpoint_url=args.s3_endpoint,
        aws_access_key_id=args.s3_access_key,
        aws_secret_access_key=args.s3_secret_key,
        config=BotoConfig(signature_version="s3v4"),
        region_name="us-east-1",
    )

    # Ensure bucket exists
    try:
        s3.head_bucket(Bucket=args.s3_bucket)
    except s3.exceptions.ClientError:
        print(f"Creating bucket '{args.s3_bucket}'...")
        s3.create_bucket(Bucket=args.s3_bucket)

    # 2. Upload file to S3
    filename = args.file.split("/")[-1]
    s3_key = f"uploads/{filename}"
    print(f"Uploading '{args.file}' to s3://{args.s3_bucket}/{s3_key} ...")
    s3.upload_file(args.file, args.s3_bucket, s3_key)
    print("Upload complete.")

    # 3. Generate presigned URL using Docker DNS endpoint
    s3_presigned = boto3.client(
        "s3",
        endpoint_url=args.presigned_endpoint,
        aws_access_key_id=args.s3_access_key,
        aws_secret_access_key=args.s3_secret_key,
        config=BotoConfig(signature_version="s3v4"),
        region_name="us-east-1",
    )
    presigned_url = s3_presigned.generate_presigned_url(
        "get_object",
        Params={"Bucket": args.s3_bucket, "Key": s3_key},
        ExpiresIn=args.url_expiry,
    )
    print(f"Presigned URL: {presigned_url}")

    # 4. Send scan request to the API
    scan_endpoint = f"{args.api_url}/api/v1/scan/url"
    print(f"\nSending scan request to {scan_endpoint} ...")
    response = httpx.post(
        scan_endpoint, json={"presigned_url": presigned_url}, timeout=60
    )

    # 5. Print result
    print(f"Status code: {response.status_code}\n")
    result = response.json()
    print(json.dumps(result, indent=2))

    # Exit with non-zero code if infected or error
    if response.status_code != 200:
        sys.exit(1)
    if result.get("infected_files", 0) > 0:
        print("\nResult: INFECTED")
        sys.exit(2)
    if result.get("error_files", 0) > 0:
        print("\nResult: ERROR")
        sys.exit(3)
    print("\nResult: CLEAN")


if __name__ == "__main__":
    main()
