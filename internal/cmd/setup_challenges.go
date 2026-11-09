package cmd

import (
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/urfave/cli/v2"
)

func setupChallenges(ctx *cli.Context, client *lego.Client) {
	if !ctx.IsSet(flgDNS) {
		log.Fatalf("You must specify the DNS challenge: `--%s`.", flgDNS)
	}

	if ctx.IsSet(flgDNS) {
		err := setupDNS(ctx, client)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func setupDNS(ctx *cli.Context, client *lego.Client) error {
	err := checkPropagationExclusiveOptions(ctx)
	if err != nil {
		return err
	}

	wait := ctx.Duration(flgDNSPropagationWait)
	if wait < 0 {
		return fmt.Errorf("'%s' cannot be negative", flgDNSPropagationWait)
	}

	provider, err := dns.NewDNSChallengeProviderByName(ctx.String(flgDNS))
	if err != nil {
		return err
	}

	servers := ctx.StringSlice(flgDNSResolvers)

	err = client.Challenge.SetDNS01Provider(provider,
		dns01.CondOption(len(servers) > 0,
			dns01.AddRecursiveNameservers(dns01.ParseNameservers(ctx.StringSlice(flgDNSResolvers)))),

		dns01.CondOption(ctx.Bool(flgDNSDisableCP) || ctx.Bool(flgDNSPropagationDisableANS),
			dns01.DisableAuthoritativeNssPropagationRequirement()),

		dns01.CondOption(ctx.Duration(flgDNSPropagationWait) > 0,
			// TODO(ldez): inside the next major version we will use flgDNSDisableCP here.
			// This will change the meaning of this flag to really disable all propagation checks.
			dns01.PropagationWait(wait, true)),

		dns01.CondOption(ctx.Bool(flgDNSPropagationRNS),
			dns01.RecursiveNSsPropagationRequirement()),

		dns01.CondOption(ctx.IsSet(flgDNSTimeout),
			dns01.AddDNSTimeout(time.Duration(ctx.Int(flgDNSTimeout))*time.Second)),
	)

	return err
}

func checkPropagationExclusiveOptions(ctx *cli.Context) error {
	if ctx.IsSet(flgDNSDisableCP) {
		log.Printf("The flag '%s' is deprecated use '%s' instead.", flgDNSDisableCP, flgDNSPropagationDisableANS)
	}

	if (isSetBool(ctx, flgDNSDisableCP) || isSetBool(ctx, flgDNSPropagationDisableANS)) && ctx.IsSet(flgDNSPropagationWait) {
		return fmt.Errorf("'%s' and '%s' are mutually exclusive", flgDNSPropagationDisableANS, flgDNSPropagationWait)
	}

	if isSetBool(ctx, flgDNSPropagationRNS) && ctx.IsSet(flgDNSPropagationWait) {
		return fmt.Errorf("'%s' and '%s' are mutually exclusive", flgDNSPropagationRNS, flgDNSPropagationWait)
	}

	return nil
}

func isSetBool(ctx *cli.Context, name string) bool {
	return ctx.IsSet(name) && ctx.Bool(name)
}
