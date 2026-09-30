package config

import "testing"

// D9b: tools.outboundWebhooks.queueUrl, the one knob the webhook queue adds.
// Empty is the in-process deliverer and is the default (defaults_test.go); a
// value must at least be shaped like the URL SQS reports for a queue.

func TestWebhookQueueURLAcceptsAnSQSQueueURL(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://sqs.eu-west-1.amazonaws.com/000000000000/awesome-auth-webhooks",
		"  https://sqs.us-east-1.amazonaws.com/000000000000/q  ",
	} {
		doc := baseDoc()
		set(doc, "tools.outboundWebhooks.queueUrl", raw)
		if _, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())}); err != nil {
			t.Errorf("%q refused: %v", raw, err)
		}
	}
}

func TestWebhookQueueURLRefusesWhatIsNotAQueueURL(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"sqs.eu-west-1.amazonaws.com/000000000000/q", // no scheme
		"http://sqs.eu-west-1.amazonaws.com/000000000000/q",
		"https://sqs.eu-west-1.amazonaws.com/", // no queue
		"awesome-auth-webhooks",                // a name, not a URL
	} {
		doc := baseDoc()
		set(doc, "tools.outboundWebhooks.queueUrl", raw)
		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		requireRule(t, err, "", "tools.outboundWebhooks.queueUrl")
	}
}

func TestWebhookQueueURLComesFromItsVariable(t *testing.T) {
	t.Parallel()
	env := baseEnv()
	env["AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_QUEUE_URL"] = "https://sqs.eu-west-1.amazonaws.com/000000000000/q"
	cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tools.OutboundWebhooks.QueueURL != env["AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_QUEUE_URL"] {
		t.Errorf("queueUrl = %q", cfg.Tools.OutboundWebhooks.QueueURL)
	}
}
