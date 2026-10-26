// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const vmID = "misc.vm-tuning"

type vmTuning struct{ control.Base }

func init() {
	System.Add(&vmTuning{control.Base{M: control.Meta{
		ID:       vmID,
		Category: control.Misc,
		Number:   3,
		Title:    "Tune virtual memory settings",
		Default:  false,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

func rangeInput(key, label, def, help string, min, max int) control.Input {
	in := numberInput(key, label, def, min, max)
	in.Help = help
	return in
}

func (v *vmTuning) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		rangeInput("swappiness", "How eagerly the kernel swaps (vm.swappiness)", "10", "0 to 100. Low values keep programs in RAM.", 0, 100),
		rangeInput("pressure", "How eagerly it drops cached file names (vm.vfs_cache_pressure)", "50", "1 to 1000. Below 100 keeps the cache longer.", 1, 1000),
	}, nil
}

func (v *vmTuning) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sysctlCheck(ctx, env, vmID, "vm")
}

func (v *vmTuning) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	sw, pr := strings.TrimSpace(in.String("swappiness")), strings.TrimSpace(in.String("pressure"))
	if n, err := strconv.Atoi(sw); err != nil || n < 0 || n > 100 {
		return fmt.Errorf("swappiness %q is not a number from 0 to 100", sw)
	}
	if n, err := strconv.Atoi(pr); err != nil || n < 1 || n > 1000 {
		return fmt.Errorf("the cache pressure %q is not a number from 1 to 1000", pr)
	}
	if _, err := sysctlApply(ctx, env, vmID, "vm", []setting{
		{"vm.swappiness", sw},
		{"vm.vfs_cache_pressure", pr},
	}); err != nil {
		return err
	}
	return nil
}

func (v *vmTuning) Revert(ctx context.Context, env *control.Env) error {
	return sysctlRevert(ctx, env, vmID, "vm")
}
