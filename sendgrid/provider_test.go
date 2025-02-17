package sendgrid_test

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/trois-six/terraform-provider-sendgrid/sendgrid"
)

var testAccProviderFactories map[string]func() (*schema.Provider, error) //nolint:gochecknoglobals

var testAccProvider *schema.Provider

func init() {
	testAccProvider = sendgrid.Provider()
	testAccProviderFactories = map[string]func() (*schema.Provider, error){
		"sendgrid": func() (*schema.Provider, error) {
			return testAccProvider, nil
		},
	}
}

func TestProvider(t *testing.T) {
	if err := sendgrid.Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = sendgrid.Provider()
}

func testAccPreCheck(t *testing.T) {
	t.Helper()

	if err := os.Getenv("SENDGRID_API_KEY"); err == "" {
		t.Fatal("SENDGRID_API_KEY must be set for acceptance tests")
	}
}
