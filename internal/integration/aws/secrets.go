package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// SecretRefKeySeparator selects one key out of a secret that stores a JSON
// document rather than a bare string — the shape the Secrets Manager console
// produces, and the one an RDS or an OAuth credential pair naturally has:
//
//	secretsManager: awesome-auth/prod/jwt#accessTokenSecret
//	ssmParameter:   /awesome-auth/prod/jwt#accessTokenSecret
//
// docs/spec/config-schema.md specifies no selector syntax, so this one is a
// choice, documented in that file's §1 conventions. '#' is safe as a separator
// because neither store allows it in a name: Secrets Manager names are
// alphanumeric plus /_+=.@- and an ARN is colon-delimited, and SSM parameter
// names are alphanumeric plus ._-/ . A reference with no separator is used
// whole and the stored value is returned verbatim — there is no guessing at a
// JSON document that was never asked for, because a secret whose value happens
// to start with '{' would then resolve differently from one that does not.
const SecretRefKeySeparator = "#"

// SecretsManagerAPI is the single Secrets Manager call the resolver makes.
// Declared here rather than imported so tests inject a fake instead of a
// socket, the same way internal/store/dynamodb takes its client.
type SecretsManagerAPI interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// SSMAPI is the single Parameter Store call the resolver makes.
type SSMAPI interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// SecretResolverOptions configures NewSecretResolvers. The zero value is what
// a Lambda uses: the ambient credential chain, the ambient region, real
// clients built on first use.
type SecretResolverOptions struct {
	// Region overrides the region the default config chain resolves. Empty
	// falls back to AWS_REGION, which the Lambda runtime always sets.
	//
	// It is deliberately not wired to stores.connection.region: secrets are
	// resolved *inside* config.Load, so no knob of the configuration being
	// loaded is known yet. A secret in another region is an explicit ARN.
	Region string

	// SecretsManager and SSM inject clients. Non-nil skips the lazy build,
	// which is how tests drive the resolvers without an AWS account.
	SecretsManager SecretsManagerAPI
	SSM            SSMAPI
}

// NewSecretResolvers builds the AWS-backed halves of config.Resolvers.
//
// It performs no I/O and cannot fail, which is the point: cmd/auth has to wire
// the chain *before* config.Load runs, and a deployment whose secrets all come
// from the environment must not pay for an SDK client it never calls. The
// clients are built on the first Resolve that actually needs one; the Env
// resolver is left nil for config.Load to default over its own Getenv.
func NewSecretResolvers(opts SecretResolverOptions) config.Resolvers {
	shared := &lazyConfig{region: opts.Region}

	sm := &SecretsManagerResolver{cache: newSecretCache()}
	if opts.SecretsManager != nil {
		sm.client = func(context.Context) (SecretsManagerAPI, error) { return opts.SecretsManager, nil }
	} else {
		sm.client = func(ctx context.Context) (SecretsManagerAPI, error) {
			cfg, err := shared.get(ctx)
			if err != nil {
				return nil, err
			}
			return secretsmanager.NewFromConfig(cfg), nil
		}
	}

	ps := &SSMResolver{cache: newSecretCache()}
	if opts.SSM != nil {
		ps.client = func(context.Context) (SSMAPI, error) { return opts.SSM, nil }
	} else {
		ps.client = func(ctx context.Context) (SSMAPI, error) {
			cfg, err := shared.get(ctx)
			if err != nil {
				return nil, err
			}
			return ssm.NewFromConfig(cfg), nil
		}
	}

	return config.Resolvers{SecretsManager: sm, SSM: ps}
}

// lazyConfig loads the ambient AWS configuration at most once. Two resolvers
// and, in principle, the DynamoDB client all want the same credential chain;
// walking it three times is three times the cold-start cost for one answer.
type lazyConfig struct {
	region string

	// profile selects a named profile out of the shared config file. It is
	// always empty in the Lambda — the runtime supplies credentials through the
	// environment and there is no shared config file to read — and it exists for
	// cmd/migrate, which is an operator tool run from a workstation against two
	// accounts at once. Empty keeps the default chain exactly as it was.
	profile string

	once sync.Once
	cfg  awssdk.Config
	err  error
}

func (l *lazyConfig) get(ctx context.Context) (awssdk.Config, error) {
	l.once.Do(func() {
		var loadOpts []func(*awsconfig.LoadOptions) error
		if l.region != "" {
			loadOpts = append(loadOpts, awsconfig.WithRegion(l.region))
		}
		if l.profile != "" {
			loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(l.profile))
		}
		l.cfg, l.err = awsconfig.LoadDefaultConfig(ctx, loadOpts...)
		if l.err != nil {
			l.err = fmt.Errorf("aws: load default configuration: %w", l.err)
		}
	})
	return l.cfg, l.err
}

// SecretsManagerResolver reads secrets from AWS Secrets Manager.
//
// It implements config.SecretResolver and holds no configuration of its own:
// the reference in the document names the secret, and everything else comes
// from the execution role. Values are cached for the life of the execution
// environment — see secretCache.
type SecretsManagerResolver struct {
	client func(context.Context) (SecretsManagerAPI, error)
	cache  *secretCache
}

// Name implements config.SecretResolver.
func (r *SecretsManagerResolver) Name() string { return config.ResolverSecretsManager }

// Resolve implements config.SecretResolver.
func (r *SecretsManagerResolver) Resolve(ctx context.Context, ref string) (string, error) {
	id, key := splitSecretRef(ref)
	payload, err := r.cache.get(id, func() (string, error) { return r.fetch(ctx, id) })
	if err != nil {
		return "", err
	}
	return selectFromPayload(payload, key, ref, "Secrets Manager secret")
}

func (r *SecretsManagerResolver) fetch(ctx context.Context, id string) (string, error) {
	api, err := r.client(ctx)
	if err != nil {
		return "", fmt.Errorf("secretsmanager: cannot build a client for %q: %w", id, err)
	}
	out, err := api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: awssdk.String(id)})
	if err != nil {
		// Only "there is no such secret" falls through to the next store in the
		// resolution order. A denied read, a throttle or a scheduled-deletion
		// error must stop the walk: config.resolveOne turns anything that is not
		// ErrSecretNotFound into a refuse-to-start naming the knob, and that is
		// far better than coming up with an empty signing key.
		var missing *smtypes.ResourceNotFoundException
		if errors.As(err, &missing) {
			return "", fmt.Errorf("%w: Secrets Manager has no secret %q", config.ErrSecretNotFound, id)
		}
		return "", fmt.Errorf("secretsmanager: reading %q failed: %w", id, err)
	}
	if out.SecretString == nil {
		// SecretBinary is a legitimate shape, just not one a signing key or an
		// API token has; decoding it here would only guess at an encoding.
		return "", fmt.Errorf("secretsmanager: secret %q holds a binary value, and this build reads SecretString only", id)
	}
	return *out.SecretString, nil
}

// SSMResolver reads secrets from SSM Parameter Store, decrypting SecureString
// parameters with the KMS key they were written under.
type SSMResolver struct {
	client func(context.Context) (SSMAPI, error)
	cache  *secretCache
}

// Name implements config.SecretResolver.
func (r *SSMResolver) Name() string { return config.ResolverSSM }

// Resolve implements config.SecretResolver.
func (r *SSMResolver) Resolve(ctx context.Context, ref string) (string, error) {
	name, key := splitSecretRef(ref)
	payload, err := r.cache.get(name, func() (string, error) { return r.fetch(ctx, name) })
	if err != nil {
		return "", err
	}
	return selectFromPayload(payload, key, ref, "SSM parameter")
}

func (r *SSMResolver) fetch(ctx context.Context, name string) (string, error) {
	api, err := r.client(ctx)
	if err != nil {
		return "", fmt.Errorf("ssm: cannot build a client for %q: %w", name, err)
	}
	// WithDecryption is unconditional: a secret-valued knob has no business in a
	// plaintext String parameter, and the flag is simply ignored for one. The
	// execution role therefore also needs kms:Decrypt when the parameter is
	// encrypted with a customer-managed key; the AWS-managed aws/ssm key needs
	// no extra grant.
	out, err := api.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           awssdk.String(name),
		WithDecryption: awssdk.Bool(true),
	})
	if err != nil {
		var missing *ssmtypes.ParameterNotFound
		if errors.As(err, &missing) {
			return "", fmt.Errorf("%w: SSM has no parameter %q", config.ErrSecretNotFound, name)
		}
		return "", fmt.Errorf("ssm: reading %q failed: %w", name, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("%w: SSM parameter %q has no value", config.ErrSecretNotFound, name)
	}
	return *out.Parameter.Value, nil
}

// secretCache memoises one fetch per store reference for the life of the
// execution environment.
//
// Resolution happens once, at cold start, so in the common case the cache saves
// nothing — until two knobs point at two keys of the same JSON secret, which is
// the shape the '#key' selector exists for. What it does guarantee is that no
// code path can turn secret resolution into a per-request call: a Secrets
// Manager read is ~20 ms of network on the init path, it is billed per 10 000
// calls, and it throttles. Adding one to every login would be the expensive
// mistake this type makes unavailable.
//
// The one value that has to follow a rotation without the environment being
// recycled — the origin check's front-door secret — is not a knob resolved
// here: SecretStagesReader reads it, around this cache on purpose, on an
// interval its caller bounds (secret_stages.go).
//
// Only definitive answers are cached — a value, or "no such secret". A denied
// read or a throttle is transient by nature and caching it would freeze a
// half-broken container until the platform recycled it.
type secretCache struct {
	mu      sync.Mutex
	entries map[string]cachedSecret
}

type cachedSecret struct {
	value string
	err   error
}

func newSecretCache() *secretCache { return &secretCache{entries: map[string]cachedSecret{}} }

func (c *secretCache) get(key string, fetch func() (string, error)) (string, error) {
	// The lock is held across the fetch on purpose. Cold-start resolution is
	// sequential, so there is nothing to serialise in practice, and if a second
	// goroutine ever did arrive, waiting for the first answer is exactly the
	// behaviour wanted — not a second call to the same API.
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[key]; ok {
		return e.value, e.err
	}
	v, err := fetch()
	if err == nil || errors.Is(err, config.ErrSecretNotFound) {
		c.entries[key] = cachedSecret{value: v, err: err}
	}
	return v, err
}

// splitSecretRef separates the store reference from the optional JSON key
// selector. LastIndex, so that the selector is the tail even if a future name
// syntax ever allows the separator earlier.
func splitSecretRef(ref string) (id, jsonKey string) {
	if i := strings.LastIndex(ref, SecretRefKeySeparator); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

// selectFromPayload turns a fetched payload into the knob's value, applying the
// JSON key selector when the reference carries one.
//
// Every error here names the reference and never the payload, including the
// JSON decoder's — encoding/json quotes the offending input in its message
// ("invalid character 'x' looking for beginning of value"), which on a
// malformed secret would put bytes of a signing key in a CloudWatch log line.
// That is why the decode error is replaced rather than wrapped.
func selectFromPayload(payload, jsonKey, ref, kind string) (string, error) {
	if jsonKey == "" {
		if payload == "" {
			// Consistent with EnvSecretResolver: an empty value is a miss, so the
			// documented order falls through to the next store rather than
			// handing the auth core an empty signing key.
			return "", fmt.Errorf("%w: %s %q is empty", config.ErrSecretNotFound, kind, ref)
		}
		return payload, nil
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		return "", fmt.Errorf("%s %q selects the JSON key %q, but the stored value is not a JSON object", kind, ref, jsonKey)
	}
	raw, ok := doc[jsonKey]
	if !ok {
		return "", fmt.Errorf("%w: %s %q has no key %q in its JSON document", config.ErrSecretNotFound, kind, ref, jsonKey)
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("%s %q key %q is not a JSON string", kind, ref, jsonKey)
	}
	if v == "" {
		return "", fmt.Errorf("%w: %s %q key %q is empty", config.ErrSecretNotFound, kind, ref, jsonKey)
	}
	return v, nil
}
