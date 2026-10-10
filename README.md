## AWS Security Auditor

A Python + boto3 tool that scans an AWS account for common security misconfigurations — public S3 buckets, over-permissioned IAM roles, and missing encryption — and generates a plain-language report of findings.
Built as a hands-on learning project to practice the core skill of a cloud security engineer: detecting misconfigurations automatically instead of checking the console by hand.

## The Problem

Most real-world cloud breaches (Capital One, Uber, and many others) trace back to simple misconfigurations — a public bucket, an overly broad IAM policy — not sophisticated hacking. Catching these early is one of the highest-value things a security engineer does.

## What This Tool Does

Lists all S3 buckets in the account and flags any with public read/write access
Reviews IAM policies attached to users/roles and flags overly broad permissions (e.g. "Action": "*")
Outputs a simple report to the terminal (and optionally a text/JSON file) summarizing findings

## How It Works
The script uses boto3 to call AWS APIs directly:
s3_client.list_buckets() and get_bucket_acl() to check bucket exposure
iam_client.list_policies() and get_policy_version() to inspect permission scope
Each check is a small, separate function so new checks can be added easily later.

## What I Learned
Building this taught me how real cloud misconfigurations are actually detected — not through guesswork, but through specific API calls that check specific settings. Debugging boto3 permission errors also taught me a lot about how IAM itself works, which the script is designed to audit.
Status
Early-stage learning project — actively being expanded with more checks (encryption, MFA status, unused access keys).

## Tech Used

Python, boto3, AWS IAM, AWS S3, AWS CLI

## Author

Vishal Ranjan 
