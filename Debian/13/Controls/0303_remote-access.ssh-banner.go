// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	bannerID   = "remote-access.ssh-banner"
	bannerFile = "/etc/ssh/server-hardening-banner.txt"
)

// defaultBanner is a short, neutral notice.
const defaultBanner = "Authorized access only. Activity on this system is monitored and logged.\n" +
	"Disconnect now if you are not an authorized user."

type sshBanner struct{ control.Base }

func init() {
	System.Add(&sshBanner{control.Base{M: control.Meta{
		ID:       bannerID,
		Category: control.RemoteAccess,
		Number:   3,
		Title:    "Show a warning banner before login",
		Default:  true,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

func (b *sshBanner) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key:     "text",
		Label:   "Banner text",
		Help:    "Shown to everyone who connects, before they log in.",
		Kind:    control.TextArea,
		Default: defaultBanner,
		Validate: func(s string) error {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("the banner cannot be empty")
			}
			if len(s) > 4096 {
				return fmt.Errorf("the banner is too long (at most 4096 characters)")
			}
			return nil
		},
	}}, nil
}

func bannerDirectives() []directive { return []directive{{"Banner", bannerFile}} }

func (b *sshBanner) Check(ctx context.Context, env *control.Env) (control.State, error) {
	st, err := sshdCheck(ctx, env, bannerID, "banner")
	if err != nil || st != control.Applied {
		return st, err
	}
	if !files.Exists(env.Path(bannerFile)) {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (b *sshBanner) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	text := strings.TrimSpace(in.String("text"))
	if text == "" {
		return fmt.Errorf("the banner cannot be empty")
	}
	if err := env.Rec.Backup(bannerID, env.Path(bannerFile)); err != nil {
		return err
	}
	if err := files.WriteAtomic(env.Path(bannerFile), []byte(text+"\n"), 0o644); err != nil {
		return err
	}
	if err := sshdApply(ctx, env, bannerID, "banner", bannerDirectives()); err != nil {
		_, _ = env.Rec.Restore(bannerID, env.Path(bannerFile))
		return err
	}
	env.Log.Infof("the banner is shown before login")
	return nil
}

func (b *sshBanner) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(bannerID) {
		env.Log.Warnf("%s: no record, leaving the banner alone", bannerID)
		return nil
	}
	// Take the setting out first, so sshd never points at a missing file.
	if _, err := env.Rec.Restore(bannerID, env.Path(sshdFile("banner"))); err != nil {
		return err
	}
	if err := sshdValidate(ctx, env); err != nil {
		return fmt.Errorf("sshd refuses the configuration after the revert: %w", err)
	}
	if err := sshdReload(ctx, env); err != nil {
		return err
	}
	if _, err := env.Rec.Restore(bannerID, env.Path(bannerFile)); err != nil {
		return err
	}
	return env.Rec.Delete(bannerID)
}
