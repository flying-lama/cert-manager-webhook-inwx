package main

import (
	"os"
	"testing"
	"time"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	fixture := acmetest.NewFixture(&inwxDNSProviderSolver{},
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath("testdata/inwx"),
		acmetest.SetStrict(true),
		acmetest.SetDNSServer("ns.ote.inwx.de:53"),
		acmetest.SetPropagationLimit(time.Second*5),
	)

	fixture.RunConformance(t)
}
