#!/usr/bin/env bash
# Package and deploy infra/sam/template.yaml with the plain AWS CLI.
#
#   ./scripts/deploy.sh --profile <profile> --region <region> [options]
#
# There is no SAM CLI anywhere in this workflow and none is needed: the
# AWS::Serverless-2016-10-31 transform is applied server-side by CloudFormation,
# so `aws cloudformation package` + `aws cloudformation deploy` is the whole of
# `sam deploy`. Removing that dependency is deliberate — a quickstart that only
# works if you first install a second CLI is not a quickstart.
#
# --profile and --region are REQUIRED and have no defaults. That is not
# pedantry: an omitted --profile silently targets whatever `default` happens to
# be, which for anyone with more than one AWS account is the wrong one, and the
# mistake is only visible after a stack exists in it. The script also prints the
# account it resolved and refuses to continue without confirmation (or --yes).
#
# What it does, in order:
#   1. checks every artifact the template names exists and has a `bootstrap`
#   2. ensures a private, encrypted, versioned S3 bucket for the upload
#   3. `cloudformation package`  — uploads the zips, rewrites each CodeUri to an S3 URI
#   4. `cloudformation deploy`   — creates or updates the stack
#   5. prints the stack outputs
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE="${REPO_ROOT}/infra/sam/template.yaml"
# Every artifact the template names in a CodeUri, not only the auth function's:
# `cloudformation package` uploads each CodeUri whatever the function's
# Condition, so a stack with EnableWebhookQueue off still needs the webhook
# worker's zip to package (D9b), and one with EnableInboundWebhooks off the
# script runner's (D9d). Read from the template so that the next function is
# checked without anybody remembering to add it here.
# A read loop rather than mapfile, which the bash 3.2 macOS ships lacks.
ARTIFACTS=()
while IFS= read -r a; do
  ARTIFACTS+=("${a}")
done < <(sed -n 's#^[[:space:]]*CodeUri:[[:space:]]*\.\./\.\./\(dist/[A-Za-z0-9._-]*-lambda\.zip\)[[:space:]]*$#\1#p' "${TEMPLATE}" | sort -u)
PACKAGED="${REPO_ROOT}/dist/packaged.yaml"

PROFILE=""
REGION=""
STACK_NAME="awesome-lambda-auth"
ARTIFACT_BUCKET=""
ASSUME_YES=0
BUILD=0
PARAM_OVERRIDES=()

usage() {
  cat >&2 <<'EOF'
usage: scripts/deploy.sh --profile <profile> --region <region> [options]

required:
  --profile <name>          AWS CLI profile. No default, on purpose.
  --region  <name>          AWS region. No default, on purpose.

options:
  --stack-name <name>       CloudFormation stack name (default: awesome-lambda-auth)
  --artifact-bucket <name>  S3 bucket for the Lambda zip. Default is
                            awesome-lambda-auth-artifacts-<account-id>-<region>,
                            computed at run time and created if missing.
  --parameter Key=Value     Template parameter override. Repeatable.
  --build                   Run scripts/build-lambda.sh first.
  --yes                     Skip the "deploying into account X" confirmation.
  -h, --help                This.

examples:
  scripts/deploy.sh --profile <profile> --region <region> --build
  scripts/deploy.sh --profile <profile> --region <region> \
      --stack-name auth-prod \
      --parameter PublicUrl=https://auth.example.com \
      --parameter AllowInsecureCookieMode=false \
      --parameter DeploymentEnvironment=production
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --profile)          PROFILE="${2:?--profile needs a value}"; shift 2 ;;
    --region)           REGION="${2:?--region needs a value}"; shift 2 ;;
    --stack-name)       STACK_NAME="${2:?--stack-name needs a value}"; shift 2 ;;
    --artifact-bucket)  ARTIFACT_BUCKET="${2:?--artifact-bucket needs a value}"; shift 2 ;;
    --parameter)        PARAM_OVERRIDES+=("${2:?--parameter needs Key=Value}"); shift 2 ;;
    --build)            BUILD=1; shift ;;
    --yes)              ASSUME_YES=1; shift ;;
    -h|--help)          usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

die() { echo "deploy: $*" >&2; exit 1; }

# Explicit, always. AWS_PROFILE / AWS_DEFAULT_REGION in the environment are
# deliberately NOT consulted: an inherited variable is exactly the kind of
# invisible state that puts a stack in the wrong account.
[ -n "${PROFILE}" ] || { echo "deploy: --profile is required and has no default." >&2; usage; exit 2; }
[ -n "${REGION}" ]  || { echo "deploy: --region is required and has no default." >&2; usage; exit 2; }

command -v aws >/dev/null 2>&1 || die "the AWS CLI is not on PATH"

AWS=(aws --profile "${PROFILE}" --region "${REGION}")

if [ "${BUILD}" -eq 1 ]; then
  echo "==> building the Lambda artifacts"
  names=""
  for a in "${ARTIFACTS[@]}"; do
    n="$(basename "${a}")"
    names="${names} ${n%-lambda.zip}"
  done
  LAMBDAS="${names# }" "${SCRIPT_DIR}/build-lambda.sh"
fi

# A zip that does not contain a root-level `bootstrap` deploys fine and then
# fails every invocation with Runtime.InvalidEntrypoint, which is a slow way to
# find out. Check before uploading, not after — every artifact, for the reason
# ARTIFACTS is read from the template.
[ "${#ARTIFACTS[@]}" -gt 0 ] || die "found no CodeUri under dist/ in ${TEMPLATE}; this script no longer understands the template"
for a in "${ARTIFACTS[@]}"; do
  ARTIFACT="${REPO_ROOT}/${a}"
  n="$(basename "${a}")"
  [ -f "${ARTIFACT}" ] || die "missing ${ARTIFACT} — run LAMBDAS=\"${n%-lambda.zip}\" scripts/build-lambda.sh (or pass --build, which builds every artifact the template names)"
  if command -v unzip >/dev/null 2>&1; then
    unzip -l "${ARTIFACT}" | grep -qE '[[:space:]]bootstrap$' \
      || die "${ARTIFACT} has no root-level 'bootstrap' entry; provided.al2023 will refuse it"
  else
    echo "note: unzip not found, skipping the bootstrap-entry check" >&2
  fi
done

echo "==> resolving caller identity"
IDENTITY_JSON="$("${AWS[@]}" sts get-caller-identity --output json)" \
  || die "sts get-caller-identity failed for profile '${PROFILE}'"
ACCOUNT_ID="$(printf '%s' "${IDENTITY_JSON}" | sed -n 's/.*"Account"[[:space:]]*:[[:space:]]*"\([0-9]*\)".*/\1/p')"
CALLER_ARN="$(printf '%s' "${IDENTITY_JSON}" | sed -n 's/.*"Arn"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
[ -n "${ACCOUNT_ID}" ] || die "could not parse the account id out of sts get-caller-identity"

if [ -z "${ARTIFACT_BUCKET}" ]; then
  # Account id and region make it globally unique without anyone inventing a
  # name, and neither value is ever written into a tracked file.
  ARTIFACT_BUCKET="awesome-lambda-auth-artifacts-${ACCOUNT_ID}-${REGION}"
fi

cat <<EOF

  profile          ${PROFILE}
  region           ${REGION}
  account          ${ACCOUNT_ID}
  caller           ${CALLER_ARN}
  stack            ${STACK_NAME}
  artifact bucket  ${ARTIFACT_BUCKET}
  artifacts        ${ARTIFACTS[*]}

EOF

if [ "${ASSUME_YES}" -ne 1 ]; then
  if [ -t 0 ]; then
    printf 'Deploy into account %s? [y/N] ' "${ACCOUNT_ID}"
    read -r reply
    case "${reply}" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
  else
    die "not a terminal and --yes was not given; refusing to deploy unconfirmed"
  fi
fi

# ---------------------------------------------------------------------------
# Artifact bucket
#
# Private, encrypted, versioned, public access blocked. It holds deployable code
# for an authentication service; a world-readable bucket of Lambda zips is a
# supply-chain problem, and versioning is what lets you roll back to the exact
# bytes that were running.
# ---------------------------------------------------------------------------
echo "==> ensuring s3://${ARTIFACT_BUCKET}"
if "${AWS[@]}" s3api head-bucket --bucket "${ARTIFACT_BUCKET}" >/dev/null 2>&1; then
  echo "    exists"
else
  echo "    creating"
  if [ "${REGION}" = "us-east-1" ]; then
    # us-east-1 is the one region where CreateBucket rejects a
    # LocationConstraint instead of requiring it.
    "${AWS[@]}" s3api create-bucket --bucket "${ARTIFACT_BUCKET}" >/dev/null
  else
    "${AWS[@]}" s3api create-bucket --bucket "${ARTIFACT_BUCKET}" \
      --create-bucket-configuration "LocationConstraint=${REGION}" >/dev/null
  fi
  "${AWS[@]}" s3api put-public-access-block --bucket "${ARTIFACT_BUCKET}" \
    --public-access-block-configuration \
    'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true' >/dev/null
  "${AWS[@]}" s3api put-bucket-encryption --bucket "${ARTIFACT_BUCKET}" \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}' >/dev/null
  "${AWS[@]}" s3api put-bucket-versioning --bucket "${ARTIFACT_BUCKET}" \
    --versioning-configuration 'Status=Enabled' >/dev/null
fi

echo "==> cloudformation package"
mkdir -p "$(dirname -- "${PACKAGED}")"
"${AWS[@]}" cloudformation package \
  --template-file "${TEMPLATE}" \
  --s3-bucket "${ARTIFACT_BUCKET}" \
  --s3-prefix "${STACK_NAME}" \
  --output-template-file "${PACKAGED}"

echo "==> cloudformation deploy"
# CAPABILITY_IAM        the function's execution role
# CAPABILITY_AUTO_EXPAND the AWS::Serverless-2016-10-31 transform
# No CAPABILITY_NAMED_IAM: nothing in the template names an IAM resource, so
# granting it would only widen what a future template edit could do unnoticed.
deploy_args=(
  cloudformation deploy
  --template-file "${PACKAGED}"
  --stack-name "${STACK_NAME}"
  --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND
  --no-fail-on-empty-changeset
  --tags "project=awesome-lambda-auth" "stack=${STACK_NAME}"
)
if [ "${#PARAM_OVERRIDES[@]}" -gt 0 ]; then
  deploy_args+=(--parameter-overrides "${PARAM_OVERRIDES[@]}")
fi
"${AWS[@]}" "${deploy_args[@]}"

echo
echo "==> stack outputs"
"${AWS[@]}" cloudformation describe-stacks \
  --stack-name "${STACK_NAME}" \
  --query 'Stacks[0].Outputs[].{Key:OutputKey,Value:OutputValue}' \
  --output table

cat <<EOF

Smoke test (ApiEndpoint from the table above):

  curl -sS "<ApiEndpoint>/healthz"

Tear it down with:

  scripts/teardown.sh --profile ${PROFILE} --region ${REGION} --stack-name ${STACK_NAME}
EOF
