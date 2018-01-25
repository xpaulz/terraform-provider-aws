
package aws

import (
	"fmt"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/aws/aws-sdk-go/service/sts"

)

func dataSourceAwsIamSamlProvider() *schema.Resource {
        return &schema.Resource{
                Read: dataSourceAwsIamSamlProviderRead,
                
                Schema: map[string]*schema.Schema{
                        "arn": {
                                Type:     schema.TypeString,
                                Optional: true
                        },
                        "valid_until" {
                                Type:     schema.TypeString,
                                Computed: true,
                        },
			// seems like we ought to be able to filter
			// based on the "valid_until" and "create_date" attributes
			// but since the resourceAwsIamSamlProvider omits "create_date"
                        // "create_date" {
			// 	Type:     schema.TypeString,
                        //	Computed: true,
                        //},
                        "saml_metadata_document": {
                 		Type:     schema.TypeString,
				Computed: true,
			},
                        "name": {
                                Type:     schema.TypeString,
                                Optional: true
                        }
                }
        }
}

func dataSourceAwsIamSamlProviderRead(d *schema.ResourceData, meta interface{}}) error {
        name, hasName := d.GetOk("name")
        arn, hasArn := d.GetOk("arn")
        
        var id string
        if hasArn { 
		// silently ignoring any "name", if set
                id := arn.(string)
        } else if hasName {
        
                resourcePath := "saml-provider/" + name
                partition := meta.(*AWSClient).partition,
                
		# res, err := meta.(*AWSClient).stsconn.getCallerIdentity(&sts.GetCallerIdentityInput{})
                # accountid := res.Account
		accountid := &dataSourceAwsIamSamlProviderGetAccountId(meta)

                id := &iamArnString(partition, accountid, resourcePath)

	} else { 
                return fmt.Errorf("`%s` must be set", "arn")
        }
	
	d.SetId(id)
	
	data := &resourceAwsIamSamlProviderRead(d, meta)
	// this function pre-populates the "name" attribute as well

	return data
}

func dataSourceAwsIamSamlProviderGetAccountId(meta interface{}) error {
        // perhaps this does not work in all cases, based on previous experience...
        // either federated token or assumed role or instance_profile with mfa or something cannot invoke it
        // TODO: identify and test those edge cases
        
        stsclient :=meta.(*AWSclient).stsconn
        
        log.Printf("[DEBUG]" Reading CallerIdentity")
        
        res, err := stsclient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
        if err != nil {
                return fmt.Errorf("Error getting Caller Identity: %v", err)
        }
        
        log.Printf("[DEBUG] Received Caller Identity: "%s", res)
        
        return res.Account
}
