/*
Provide a resource to manage an API key.
Example Usage
```hcl
resource "sendgrid_domain_authentication" "default" {
	domain = "example.com"
    ips = [ "10.10.10.10" ]
    is_default = true
    automatic_security = false
}
```
Import
An unsubscribe group can be imported, e.g.
```hcl
$ terraform import sendgrid_domain_authentication.default domainId
```
*/
package sendgrid

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	sendgrid "github.com/trois-six/terraform-provider-sendgrid/sdk"
)

//nolint:funlen
func resourceSendgridDomainAuthentication() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSendgridDomainAuthenticationCreate,
		ReadContext:   resourceSendgridDomainAuthenticationRead,
		UpdateContext: resourceSendgridDomainAuthenticationUpdate,
		DeleteContext: resourceSendgridDomainAuthenticationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"domain": {
				Type:        schema.TypeString,
				Description: "Domain being authenticated.",
				Required:    true,
				ForceNew:    true,
			},
			"subdomain": {
				Type:        schema.TypeString,
				Description: "The subdomain to use for this authenticated domain.",
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
			},
			"username": {
				Type:        schema.TypeString,
				Description: "The username associated with this domain.",
				Computed:    true,
			},
			"ips": {
				Type:        schema.TypeSet,
				Description: "The IP addresses that will be included in the custom SPF record for this.",
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"custom_spf": {
				Type:        schema.TypeBool,
				Description: "Specify whether to use a custom SPF or allow SendGrid to manage your SPF. This option is only available to authenticated domains set up for manual security.",
				Optional:    true,
			},
			"is_default": {
				Type:        schema.TypeBool,
				Description: "Whether to use this authenticated domain as the fallback if no authenticated domains match the sender's domain.",
				Optional:    true,
			},
			"automatic_security": {
				Type:        schema.TypeBool,
				Description: "Whether to allow SendGrid to manage your SPF records, DKIM keys, and DKIM key rotation.",
				Optional:    true,
				ForceNew:    true,
			},
			"custom_dkim_selector": {
				Type:        schema.TypeString,
				Description: "Add a custom DKIM selector. Accepts three letters or numbers.",
				Optional:    true,
				ForceNew:    true,
			},
			"valid": {
				Type:        schema.TypeBool,
				Description: "Indicates if this is a valid authenticated domain or not.",
				Optional:    true,
				Computed:    true,
			},
			"dns": {
				Type:        schema.TypeList,
				Description: "The DNS records used to authenticate the sending domain.",
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"valid": {
							Type:        schema.TypeBool,
							Description: "Indicates if this is a valid CNAME.",
							Computed:    true,
						},
						"type": {
							Type:        schema.TypeString,
							Description: "The type of DNS record.",
							Computed:    true,
						},
						"host": {
							Type:        schema.TypeString,
							Description: "The domain that this CNAME is created for.",
							Computed:    true,
						},
						"data": {
							Type:        schema.TypeString,
							Description: "The actual DNS record.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func resourceSendgridDomainAuthenticationCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*sendgrid.Client)

	domain := d.Get("domain").(string)
	subdomain := d.Get("subdomain").(string)
	customSPF := d.Get("custom_spf").(bool)
	isDefault := d.Get("is_default").(bool)
	automaticSecurity := d.Get("automatic_security").(bool)
	customDKIMSelector := d.Get("custom_dkim_selector").(string)
	ipsSet := d.Get("ips").(*schema.Set).List()
	ips := make([]string, 0)

	for _, ip := range ipsSet {
		ips = append(ips, ip.(string))
	}

	apiKeyStruct, err := sendgrid.RetryOnRateLimit(ctx, d, func() (interface{}, sendgrid.RequestError) {
		return c.CreateDomainAuthentication(domain, subdomain, ips, customSPF, isDefault, automaticSecurity, customDKIMSelector)
	})

	auth := apiKeyStruct.(*sendgrid.DomainAuthentication)

	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(fmt.Sprint(auth.ID))

	return resourceSendgridDomainAuthenticationRead(ctx, d, m)
}

func resourceSendgridDomainAuthenticationRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics { //nolint:cyclop
	c := m.(*sendgrid.Client)

	auth, err := c.ReadDomainAuthentication(d.Id())
	if err.Err != nil {
		return diag.FromErr(err.Err)
	}

	if err := d.Set("domain", auth.Domain); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("subdomain", auth.Subdomain); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("username", auth.Username); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("is_default", auth.IsDefault); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("custom_spf", auth.CustomSPF); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("custom_dkim_selector", auth.CustomDKIMSelector); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("valid", auth.Valid); err != nil {
		return diag.FromErr(err)
	}

	ips := make([]interface{}, len(auth.IPs))
	for idx, ip := range auth.IPs {
		ips[idx] = ip
	}

	if err := d.Set("ips", schema.NewSet(d.Get("ips").(*schema.Set).F, ips)); err != nil {
		return diag.FromErr(err)
	}

	dns := make([]interface{}, 0)

	if auth.DNS.DKIM1.Type != "" {
		dns = append(dns, makeDomainAuthDNSRecord(auth.DNS.DKIM1))
	}

	if auth.DNS.DKIM2.Type != "" {
		dns = append(dns, makeDomainAuthDNSRecord(auth.DNS.DKIM2))
	}

	if auth.DNS.MailCNAME.Type != "" {
		dns = append(dns, makeDomainAuthDNSRecord(auth.DNS.MailCNAME))
	}

	if err := d.Set("dns", dns); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func makeDomainAuthDNSRecord(dns sendgrid.DomainAuthenticationDNSValue) map[string]interface{} {
	return map[string]interface{}{
		"type":  dns.Type,
		"valid": dns.Valid,
		"host":  dns.Host,
		"data":  dns.Data,
	}
}

func resourceSendgridDomainAuthenticationUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*sendgrid.Client)

	isDefault := d.Get("is_default").(bool)
	customSPF := d.Get("custom_spf").(bool)

	auth, err := sendgrid.RetryOnRateLimit(ctx, d, func() (interface{}, sendgrid.RequestError) {
		return c.UpdateDomainAuthentication(d.Id(), isDefault, customSPF)
	})
	if err != nil {
		return diag.FromErr(err)
	}

	if !auth.(*sendgrid.DomainAuthentication).Valid && d.Get("valid").(bool) {
		if err := c.ValidateDomainAuthentication(d.Id()); err.Err != nil || err.StatusCode != 200 {
			if err.Err != nil {
				return diag.FromErr(err.Err)
			}

			return diag.Errorf("unable to validate domain DNS configuration")
		}
	}

	return resourceSendgridDomainAuthenticationRead(ctx, d, m)
}

func resourceSendgridDomainAuthenticationDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*sendgrid.Client)

	_, err := sendgrid.RetryOnRateLimit(ctx, d, func() (interface{}, sendgrid.RequestError) {
		return c.DeleteDomainAuthentication(d.Id())
	})
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}
