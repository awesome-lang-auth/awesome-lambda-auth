#!/usr/bin/env bash
# Delete a stack created by scripts/deploy.sh, completely.
#
#   ./scripts/teardown.sh --profile <profile> --region <region> [options]
#
# A quickstart you cannot cleanly delete is a trap, and "delete the stack" is
# not by itself a clean delete. Three things outlive it:
#
#   1. DynamoDB deletion protection, if it was turned on. The stack delete fails
#      on the table and rolls back, leaving everything else in place.
#   2. The two generated signing secrets. CloudFormation does not delete a
#      Secrets Manager secret — it *schedules* the deletion with a recovery
#      window of up to 30 days, and the name stays reserved for that long.
#      Harmless here (the template lets Secrets Manager pick the names), but the
#      secrets are billed monthly until the window expires.
#   3. The S3 artifact bucket, which the stack does not own at all.
#
# This script names all three and handles each behind an explicit flag rather
# than deleting anything the user did not ask for.
set -euo pipefail

PROFILE=""
REGION=""
STACK_NAME="awesome-lambda-auth"
ARTIFACT_BUCKET=""
DISABLE_DELETION_PROTECTION=0
PURGE_SECRETS=0
DELETE_BUCKET=0
ASSUME_YES=0

usage() {
  cat >&2 <<'EOF'
usage: scripts/teardown.sh --profile <profile> --region <region> [options]

required:
  --profile <name>                 AWS CLI profile. No default, on purpose.
  --region  <name>                 AWS region. No default, on purpose.

options:
  --stack-name <name>              Stack to delete (default: awesome-lambda-auth)
  --disable-deletion-protection    Turn DynamoDB deletion protection off first.
                                   Needed only if you deployed with
                                   EnableDeletionProtection=true.
  --purge-secrets                  After the stack is gone, force-delete the two
                                   generated signing secrets immediately instead
                                   of leaving them in the 30-day recovery
                                   window. IRREVERSIBLE. Only ever do this to a
                                   stack whose data you are also discarding —
                                   without those secrets every issued token is
                                   unverifiable.
  --delete-artifact-bucket [name]  Empty and delete the deploy bucket. Defaults
                                   to the name deploy.sh computes.
  --yes                            Skip the confirmation prompt.
  -h, --help                       This.

What the stack delete removes on its own: the DynamoDB table AND ALL USER DATA
IN IT (the template leaves DeletionPolicy at Delete so a quickstart is
disposable), the Lambda function and its execution role, the HTTP API, and the
CloudWatch log group with every log line in it. Point-in-time recovery does not
survive the table; export or back up first if any of it matters.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --profile)     PROFILE="${2:?--profile needs a value}"; shift 2 ;;
    --region)      REGION="${2:?--region needs a value}"; shift 2 ;;
    --stack-name)  STACK_NAME="${2:?--stack-name needs a value}"; shift 2 ;;
    --disable-deletion-protection) DISABLE_DELETION_PROTECTION=1; shift ;;
    --purge-secrets) PURGE_SECRETS=1; shift ;;
    --delete-artifact-bucket)
      DELETE_BUCKET=1
      # Optional inline value; anything starting with "-" is the next flag.
      if [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then ARTIFACT_BUCKET="$2"; shift 2; else shift; fi
      ;;
    --yes)         ASSUME_YES=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

die() { echo "teardown: $*" >&2; exit 1; }

[ -n "${PROFILE}" ] || { echo "teardown: --profile is required and has no default." >&2; usage; exit 2; }
[ -n "${REGION}" ]  || { echo "teardown: --region is required and has no default." >&2; usage; exit 2; }

command -v aws >/dev/null 2>&1 || die "the AWS CLI is not on PATH"

AWS=(aws --profile "${PROFILE}" --region "${REGION}")

IDENTITY_JSON="$("${AWS[@]}" sts get-caller-identity --output json)" \
  || die "sts get-caller-identity failed for profile '${PROFILE}'"
ACCOUNT_ID="$(printf '%s' "${IDENTITY_JSON}" | sed -n 's/.*"Account"[[:space:]]*:[[:space:]]*"\([0-9]*\)".*/\1/p')"
[ -n "${ACCOUNT_ID}" ] || die "could not parse the account id out of sts get-caller-identity"

"${AWS[@]}" cloudformation describe-stacks --stack-name "${STACK_NAME}" >/dev/null 2>&1 \
  || die "no stack named '${STACK_NAME}' in ${ACCOUNT_ID}/${REGION}"

TABLE_NAME="$("${AWS[@]}" cloudformation describe-stacks --stack-name "${STACK_NAME}" \
  --query "Stacks[0].Outputs[?OutputKey=='TableName'].OutputValue | [0]" --output text 2>/dev/null || true)"
[ "${TABLE_NAME}" = "None" ] && TABLE_NAME=""

# Collected before the delete, because afterwards the stack's resource list is
# gone and the secrets are only findable by ARN.
SECRET_ARNS="$("${AWS[@]}" cloudformation describe-stack-resources --stack-name "${STACK_NAME}" \
  --query "StackResources[?ResourceType=='AWS::SecretsManager::Secret'].PhysicalResourceId" \
  --output text 2>/dev/null || true)"

# D9b. The webhook queues exist only with EnableWebhookQueue; when they do, the
# stack delete destroys the dead-letter queue and every webhook that gave up
# in the last fourteen days with it, which is exactly what the DLQ was for.
QUEUE_COUNT="$("${AWS[@]}" cloudformation describe-stack-resources --stack-name "${STACK_NAME}" \
  --query "length(StackResources[?ResourceType=='AWS::SQS::Queue'])" \
  --output text 2>/dev/null || echo 0)"
QUEUE_LINE=""
if [ "${QUEUE_COUNT:-0}" != "0" ] && [ "${QUEUE_COUNT}" != "None" ]; then
  QUEUE_LINE="  webhook queues         yes, with any dead-lettered deliveries in them (read WebhookDeadLetterQueueUrl first)"
fi

if [ "${DELETE_BUCKET}" -eq 1 ] && [ -z "${ARTIFACT_BUCKET}" ]; then
  ARTIFACT_BUCKET="awesome-lambda-auth-artifacts-${ACCOUNT_ID}-${REGION}"
fi

cat <<EOF

About to delete, in ${ACCOUNT_ID}/${REGION}:

  stack                  ${STACK_NAME}
  dynamodb table         ${TABLE_NAME:-<unknown>}   (and every user, session and token in it)
  lambda + role + api    yes
  log group              yes, with its contents
${QUEUE_LINE:+${QUEUE_LINE}
}  signing secrets       $([ "${PURGE_SECRETS}" -eq 1 ] && echo 'force-deleted immediately (irreversible)' || echo 'scheduled for deletion, 30-day recovery window')
  artifact bucket        $([ "${DELETE_BUCKET}" -eq 1 ] && echo "${ARTIFACT_BUCKET} (emptied and deleted)" || echo 'left alone')

EOF

if [ "${ASSUME_YES}" -ne 1 ]; then
  if [ -t 0 ]; then
    printf 'Type the stack name to confirm: '
    read -r reply
    [ "${reply}" = "${STACK_NAME}" ] || die "aborted"
  else
    die "not a terminal and --yes was not given; refusing to delete unconfirmed"
  fi
fi

if [ "${DISABLE_DELETION_PROTECTION}" -eq 1 ]; then
  [ -n "${TABLE_NAME}" ] || die "--disable-deletion-protection given but the stack has no TableName output"
  echo "==> disabling deletion protection on ${TABLE_NAME}"
  "${AWS[@]}" dynamodb update-table --table-name "${TABLE_NAME}" \
    --no-deletion-protection-enabled >/dev/null
  # update-table returns while the table is still UPDATING, and the
  # table-exists waiter only checks that describe-table does not 404 — neither
  # tells us the flag is actually off. Poll the flag itself, or the stack delete
  # races the update and fails on the table.
  for _ in $(seq 1 30); do
    state="$("${AWS[@]}" dynamodb describe-table --table-name "${TABLE_NAME}" \
      --query 'Table.DeletionProtectionEnabled' --output text)"
    [ "${state}" = "False" ] || [ "${state}" = "false" ] || [ "${state}" = "None" ] || { sleep 2; continue; }
    break
  done
  echo "    off"
fi

echo "==> deleting stack ${STACK_NAME}"
"${AWS[@]}" cloudformation delete-stack --stack-name "${STACK_NAME}"
echo "    waiting (a few minutes)"
if ! "${AWS[@]}" cloudformation wait stack-delete-complete --stack-name "${STACK_NAME}"; then
  echo
  echo "The delete did not complete. The usual cause is DynamoDB deletion" >&2
  echo "protection — rerun with --disable-deletion-protection. Recent events:" >&2
  "${AWS[@]}" cloudformation describe-stack-events --stack-name "${STACK_NAME}" \
    --query 'StackEvents[?ResourceStatus==`DELETE_FAILED`].[LogicalResourceId,ResourceStatusReason]' \
    --output table >&2 || true
  exit 1
fi
echo "    stack deleted"

if [ "${PURGE_SECRETS}" -eq 1 ] && [ -n "${SECRET_ARNS}" ]; then
  echo "==> force-deleting the generated signing secrets"
  for arn in ${SECRET_ARNS}; do
    "${AWS[@]}" secretsmanager delete-secret --secret-id "${arn}" \
      --force-delete-without-recovery >/dev/null 2>&1 \
      && echo "    purged ${arn}" \
      || echo "    could not purge ${arn} (already gone?)" >&2
  done
elif [ -n "${SECRET_ARNS}" ]; then
  echo "==> signing secrets are scheduled for deletion with a recovery window."
  echo "    They are still billed until it expires. Purge now with:"
  for arn in ${SECRET_ARNS}; do
    echo "      aws secretsmanager delete-secret --secret-id ${arn} \\"
    echo "          --force-delete-without-recovery --profile ${PROFILE} --region ${REGION}"
  done
fi

if [ "${DELETE_BUCKET}" -eq 1 ]; then
  echo "==> emptying and deleting s3://${ARTIFACT_BUCKET}"
  if "${AWS[@]}" s3api head-bucket --bucket "${ARTIFACT_BUCKET}" >/dev/null 2>&1; then
    # The bucket is versioned, so `s3 rm --recursive` leaves every previous
    # version and every delete marker behind and the bucket delete then fails.
    for what in Versions DeleteMarkers; do
      while :; do
        keys="$("${AWS[@]}" s3api list-object-versions --bucket "${ARTIFACT_BUCKET}" \
          --max-keys 500 \
          --query "${what}[].{Key:Key,VersionId:VersionId}" --output json 2>/dev/null || echo 'null')"
        case "${keys}" in ''|null|'[]') break ;; esac
        "${AWS[@]}" s3api delete-objects --bucket "${ARTIFACT_BUCKET}" \
          --delete "{\"Objects\": ${keys}, \"Quiet\": true}" >/dev/null
      done
    done
    "${AWS[@]}" s3api delete-bucket --bucket "${ARTIFACT_BUCKET}" >/dev/null
    echo "    deleted"
  else
    echo "    no such bucket, nothing to do"
  fi
fi

echo
echo "Done. Nothing from ${STACK_NAME} is still running."
