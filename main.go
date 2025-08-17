package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"k8s.io/client-go/kubernetes"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/libdns/inwx"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&inwxDNSProviderSolver{},
	)
}

// inwxDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type inwxDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// inwxDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type inwxDNSProviderConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	UsernameSecretRef cmmeta.SecretKeySelector `json:"usernameSecretKeyRef"`
	PasswordSecretRef cmmeta.SecretKeySelector `json:"passwordSecretKeyRef"`
	OtpKeySecretRef   cmmeta.SecretKeySelector `json:"otpKeySecretKeyRef"`
	Sandbox           bool                     `json:"sandbox,omitempty"`
	Ttl               time.Duration            `json:"ttl,omitempty"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *inwxDNSProviderSolver) Name() string {
	return "inwx"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *inwxDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	cl, err := c.getInwxClient(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	r := libdns.TXT{
		Name: strings.TrimSuffix(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), "."),
		TTL:  cfg.Ttl,
		Text: ch.Key,
	}

	_, err = cl.AppendRecords(context.TODO(), ch.ResolvedZone, []libdns.Record{r})
	if err != nil {
		return fmt.Errorf("failed to set record: %v", err)
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *inwxDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	cl, err := c.getInwxClient(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	r := libdns.TXT{
		Name: strings.TrimSuffix(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), "."),
		TTL:  cfg.Ttl,
		Text: ch.Key,
	}

	_, err = cl.DeleteRecords(context.TODO(), ch.ResolvedZone, []libdns.Record{r})

	if err != nil {
		return fmt.Errorf("failed to delete record: %v", err)
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *inwxDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (inwxDNSProviderConfig, error) {
	cfg := inwxDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *inwxDNSProviderSolver) getInwxClient(cfg *inwxDNSProviderConfig, ns string) (p *inwx.Provider, err error) {
	username, err := c.getSecretFromRef(cfg.UsernameSecretRef, ns)
	if err != nil {
		err = errors.New("username secret not found: " + err.Error())
		return
	}

	password, err := c.getSecretFromRef(cfg.PasswordSecretRef, ns)
	if err != nil {
		err = errors.New("password secret not found: " + err.Error())
		return
	}

	otpKey, err := c.getSecretFromRef(cfg.OtpKeySecretRef, ns)
	if err != nil {
		err = errors.New("otpKey secret not found: " + err.Error())
		return
	}

	p = &inwx.Provider{
		Username:     username,
		Password:     password,
		SharedSecret: otpKey,
	}

	if cfg.Sandbox {
		p.EndpointURL = "https://api.ote.domrobot.com/jsonrpc/"
	}

	return
}

func (c *inwxDNSProviderSolver) getSecretFromRef(sRef cmmeta.SecretKeySelector, ns string) (string, error) {
	sName := sRef.LocalObjectReference.Name
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.Background(), sName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to get secret from namespace %s: `%s`; %v", ns, sName, err)
	}

	value, ok := secret.Data[sRef.Key]
	if ok {
		return string(value), nil
	}

	return "", fmt.Errorf("secret `%s` does not contain key `%s`", sName, sRef.Key)
}
