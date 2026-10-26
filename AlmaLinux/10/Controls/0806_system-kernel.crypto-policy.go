// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
)

const cryptoPolicyID = "system-kernel.crypto-policy"

type cryptoPolicy struct{ control.Base }

func init() {
	System.Add(&cryptoPolicy{control.Base{M: control.Meta{
		ID:       cryptoPolicyID,
		Category: control.SystemKernel,
		Number:   6,
		Title:    "Tighten the system-wide cryptographic policy",
		Default:  true,
		Tags:     []control.Tag{control.TagInput, control.TagCompat, control.TagLockout},
	}}})
}

// A policy is a base name, optionally followed by sub-policies: "DEFAULT:NO-SHA1".
var policyName = regexp.MustCompile(`^[A-Z0-9_-]+(:[A-Z0-9_-]+)*$`)

func (c *cryptoPolicy) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key: "policy", Label: "System cryptographic policy", Kind: control.Choice, Default: "DEFAULT:NO-SHA1",
		Help: "OpenSSH, TLS libraries, GnuTLS, NSS and others read this one setting. AlmaLinux does not ask for a list of SSH algorithms.",
		Options: []control.Option{
			{Value: "DEFAULT:NO-SHA1", Label: "Default without SHA-1 (recommended)"},
			{Value: "FUTURE", Label: "Future: RSA keys of 3072 bits or more only. Old keys and old clients stop working"},
		},
	}}, nil
}

// currentPolicy reads the policy that is set now.
func currentPolicy(ctx context.Context, env *control.Env) (string, error) {
	out, err := env.Run.Run(ctx, "update-crypto-policies", "--show")
	if err != nil {
		return "", fmt.Errorf("reading the cryptographic policy: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (c *cryptoPolicy) Check(ctx context.Context, env *control.Env) (control.State, error) {
	want, ok, err := env.Rec.Get(cryptoPolicyID, "wanted")
	if err != nil || !ok {
		return control.NotApplied, err
	}
	got, err := currentPolicy(ctx, env)
	if err != nil || got != want {
		return control.Partial, nil
	}
	// --check fails when the generated back-end files do not match the policy.
	if _, err := env.Run.Run(ctx, "update-crypto-policies", "--check"); err != nil {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (c *cryptoPolicy) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	policy := strings.TrimSpace(in.String("policy"))
	if !policyName.MatchString(policy) {
		return fmt.Errorf("%q is not a cryptographic policy name", policy)
	}
	if err := dnf.Install(ctx, env, "crypto-policies-scripts"); err != nil {
		return err
	}
	before, err := currentPolicy(ctx, env)
	if err != nil {
		return err
	}
	if strings.HasPrefix(before, "FIPS") {
		return fmt.Errorf("the system is in FIPS mode (%s). Leave FIPS mode with fips-mode-setup first. This control does not change it", before)
	}
	fresh := !env.Rec.Has(cryptoPolicyID)
	// A failed first run leaves no record behind. A re-run keeps the old one.
	fail := func(err error) error {
		if fresh {
			_ = env.Rec.Delete(cryptoPolicyID)
		}
		return err
	}
	if fresh {
		if err := env.Rec.Put(cryptoPolicyID, "was", before); err != nil {
			return err
		}
	}
	if err := env.Rec.Put(cryptoPolicyID, "wanted", policy); err != nil {
		return fail(err)
	}
	if before != policy {
		if _, err := env.Run.Run(ctx, "update-crypto-policies", "--set", policy); err != nil {
			return fail(fmt.Errorf("setting the policy %s: %w", policy, err))
		}
	}
	if got, err := currentPolicy(ctx, env); err != nil || got != policy {
		return fail(fmt.Errorf("the policy is %q after the change, wanted %q", got, policy))
	}
	// sshd reads the policy when it parses its configuration. If the policy
	// leaves sshd unable to start, put the old one back now.
	if err := sshdValidate(ctx, env); err != nil {
		_, _ = env.Run.Run(ctx, "update-crypto-policies", "--set", before)
		return fail(fmt.Errorf("sshd refuses its configuration under the policy %s, so the old policy %s is back: %w", policy, before, err))
	}
	if err := sshdReload(ctx, env); err != nil {
		return fail(err)
	}
	if policy == "FUTURE" {
		env.Log.Warnf("FUTURE refuses RSA keys under 3072 bits, also for logins. Open a second session and log in again before you close this one")
	}
	env.Log.Infof("policy %s is set. Programs that are already running read it again when they restart. A reboot makes sure of it", policy)
	return nil
}

func (c *cryptoPolicy) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(cryptoPolicyID) {
		env.Log.Warnf("%s: no record, leaving the cryptographic policy alone", cryptoPolicyID)
		return nil
	}
	was, _, _ := env.Rec.Get(cryptoPolicyID, "was")
	if was != "" {
		if got, err := currentPolicy(ctx, env); err != nil || got != was {
			if _, err := env.Run.Run(ctx, "update-crypto-policies", "--set", was); err != nil {
				return fmt.Errorf("setting the policy back to %s: %w", was, err)
			}
		}
	}
	if err := sshdReload(ctx, env); err != nil {
		return err
	}
	return env.Rec.Delete(cryptoPolicyID)
}
