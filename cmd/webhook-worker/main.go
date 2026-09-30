// Command webhook-worker delivers the outgoing webhooks the auth function
// enqueued (D9b).
//
// The auth function's WebhookDeliverer (internal/integration/aws,
// SQSWebhookDeliverer) puts each fully built, signed, numbered attempt on an
// SQS queue and returns once SQS has stored it; this Lambda, on that queue's
// event source with ReportBatchItemFailures, POSTs it to the receiver, retries
// it on the reference's schedule by setting the message's visibility, and hands
// it to the dead-letter queue when the subscription's attempts are spent.
// worker.go carries the per-record logic and the argument for each decision;
// this file reads the environment and starts the handler.
//
// It is a separate binary and a separate artifact (dist/webhook-worker-*.zip)
// because it needs none of the auth function: no configuration document, no
// signing secret, no route, and IAM on exactly four things — receive, delete
// and change the visibility of messages on the webhook queue, send to the DLQ,
// the ledger partition of the table, and its own log group. The role is
// written out in the template (WebhookWorkerRole) rather than generated, because
// a generated role on an SQS event source also gets the managed
// AWSLambdaSQSQueueExecutionRole, which reaches every queue in the account. A
// compromised worker can POST what is already on the queue and nothing else.
//
// # Environment
//
//	AWESOME_AUTH_WEBHOOK_QUEUE_URL             the webhook queue (for ChangeMessageVisibility)
//	AWESOME_AUTH_WEBHOOK_DLQ_URL               the dead-letter queue
//	AWESOME_AUTH_WEBHOOK_MAX_RECEIVE_COUNT     the queue's RedrivePolicy.maxReceiveCount
//	AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME  the table holding the delivery ledger
//	AWESOME_AUTH_STORES_CONNECTION_ENDPOINT    optional: DynamoDB Local, for development
//
// All but the last are required and a missing one fails the init, which the
// Lambda service reports and retries — better than a worker that acknowledges
// every message it cannot handle.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	auth "github.com/nik2208/awesome-go-auth"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

const (
	envQueueURL    = "AWESOME_AUTH_WEBHOOK_QUEUE_URL"
	envDLQURL      = "AWESOME_AUTH_WEBHOOK_DLQ_URL"
	envMaxReceives = "AWESOME_AUTH_WEBHOOK_MAX_RECEIVE_COUNT"
	envTable       = "AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME"
	envEndpoint    = "AWESOME_AUTH_STORES_CONNECTION_ENDPOINT"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(slog.String("component", "cmd/webhook-worker"))
	w, err := newWorker(context.Background(), os.LookupEnv, log)
	if err != nil {
		log.Error("webhook worker cannot start", slog.String("error", err.Error()))
		os.Exit(1)
	}
	lambda.Start(w.Handle)
}

// newWorker builds the worker from the environment. It performs no I/O: the
// DynamoDB client resolves its credentials now, as cmd/auth's does, and the
// SQS client on its first call.
func newWorker(ctx context.Context, getenv func(string) (string, bool), log *slog.Logger) (*worker, error) {
	get := func(name string) (string, error) {
		v, _ := getenv(name)
		if v = strings.TrimSpace(v); v == "" {
			return "", fmt.Errorf("%s is not set", name)
		}
		return v, nil
	}
	queueURL, err := get(envQueueURL)
	if err != nil {
		return nil, err
	}
	dlqURL, err := get(envDLQURL)
	if err != nil {
		return nil, err
	}
	table, err := get(envTable)
	if err != nil {
		return nil, err
	}
	rawMax, err := get(envMaxReceives)
	if err != nil {
		return nil, err
	}
	maxReceives, err := strconv.Atoi(rawMax)
	if err != nil || maxReceives < 1 {
		return nil, fmt.Errorf("%s must be a positive whole number, got %q", envMaxReceives, rawMax)
	}
	endpoint, _ := getenv(envEndpoint)

	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{Endpoint: strings.TrimSpace(endpoint)})
	if err != nil {
		return nil, err
	}
	store, err := ddbstore.New(client, ddbstore.Options{TableName: table, Logger: log})
	if err != nil {
		return nil, err
	}
	return &worker{
		sqs:    awsintegration.NewSQSClient(awsintegration.SQSOptions{}),
		ledger: store,
		// The core's own deliverer and its own timeout: the request a queued
		// webhook makes is the request an in-process one makes. A plain client,
		// following redirects as http.DefaultClient does, because that is what
		// the in-process path's client does too.
		deliver:     &auth.HTTPWebhookDeliverer{Client: &http.Client{}, Timeout: auth.DefaultWebhookTimeout},
		queueURL:    queueURL,
		dlqURL:      dlqURL,
		maxReceives: maxReceives,
		now:         time.Now,
		log:         log,
	}, nil
}
