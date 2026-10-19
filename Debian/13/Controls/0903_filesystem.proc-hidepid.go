// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const (
	hidepidID    = "filesystem.proc-hidepid"
	procMount    = "/proc"
	defaultGroup = "procadmin"
)

type procHidepid struct{ control.Base }

func init() {
	System.Add(&procHidepid{control.Base{M: control.Meta{
		ID:       hidepidID,
		Category: control.Filesystem,
		Number:   3,
		Title:    "Hide other users' processes",
		Default:  true,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

var groupName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func (h *procHidepid) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	admins, _ := adminAccounts(env)
	return []control.Input{
		{
			Key: "level", Label: "What ordinary users see of other users' processes", Kind: control.Choice, Default: "invisible",
			Options: []control.Option{
				{Value: "invisible", Label: "Nothing: the processes are not listed (recommended)"},
				{Value: "noaccess", Label: "Listed, but their details cannot be read"},
			},
		},
		{
			Key: "group", Label: "Group that may see all processes", Default: defaultGroup,
			Help: "Created if it does not exist. Add monitoring agents that run as an ordinary user to it.",
			Validate: func(s string) error {
				if !groupName.MatchString(strings.TrimSpace(s)) {
					return fmt.Errorf("use lowercase letters, digits, - and _, starting with a letter")
				}
				return nil
			},
		},
		{
			Key: "members", Label: "Accounts to put in that group", Optional: true,
			Default: strings.Join(admins, " "),
			Help:    "User names separated by spaces. Root does not need to be in the group.",
		},
	}, nil
}

// hidepidKey normalizes the names and the numbers of a hide level.
func hidepidKey(v string) string {
	switch v {
	case "1", "noaccess":
		return "noaccess"
	case "2", "invisible":
		return "invisible"
	case "0", "off", "":
		return "off"
	}
	return v
}

func optionValue(raw, key string) string {
	for o := range strings.SplitSeq(raw, ",") {
		if v, ok := strings.CutPrefix(o, key+"="); ok {
			return v
		}
	}
	return ""
}

func (h *procHidepid) Check(ctx context.Context, env *control.Env) (control.State, error) {
	c, err := readFstab(env)
	if err != nil {
		return control.NotApplied, err
	}
	if _, ok := fstabHas(c, procMount); !ok || !strings.Contains(c, managed(hidepidID)) {
		return control.NotApplied, nil
	}
	_, raw, err := mountOptions(ctx, env, procMount)
	if err != nil {
		return control.Partial, nil
	}
	want, _, _ := env.Rec.Get(hidepidID, "level")
	if hidepidKey(optionValue(raw, "hidepid")) != want {
		return control.Partial, nil
	}
	return control.Applied, nil
}

// gidOf reads a group's number through getent.
func gidOf(ctx context.Context, env *control.Env, group string) (int, bool) {
	out, err := env.Run.Run(ctx, "getent", "group", group)
	if err != nil {
		return 0, false
	}
	f := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(f) < 3 {
		return 0, false
	}
	n, err := strconv.Atoi(f[2])
	return n, err == nil
}

func (h *procHidepid) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	level := in.String("level")
	if level != "invisible" && level != "noaccess" {
		return fmt.Errorf("the level %q is not invisible or noaccess", level)
	}
	group := strings.TrimSpace(in.String("group"))
	if !groupName.MatchString(group) {
		return fmt.Errorf("the group name %q is not valid", group)
	}
	var members []string
	for _, m := range listItems(in.String("members")) {
		if _, ok, err := findAccount(env, m); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("there is no account %q to put in the group", m)
		}
		members = append(members, m)
	}

	fresh := !env.Rec.Has(hidepidID)
	createdHere := false
	// A failure after this point puts back what this run changed.
	fail := func(err error) error {
		_ = restoreFile(env, hidepidID, "/etc/fstab")
		_, _ = env.Run.Run(ctx, "systemctl", "daemon-reload")
		if createdHere {
			_, _ = env.Run.Run(ctx, "groupdel", group)
		}
		if fresh {
			_ = env.Rec.Delete(hidepidID)
		}
		return err
	}

	// What the mount point looks like now, for the revert.
	_, raw, err := mountOptions(ctx, env, procMount)
	if err != nil {
		return err
	}
	if !env.Rec.Has(hidepidID) {
		gid := optionValue(raw, "gid")
		if gid == "" {
			gid = "0"
		}
		for k, v := range map[string]string{"prev-hidepid": hidepidKey(optionValue(raw, "hidepid")), "prev-gid": gid} {
			if err := env.Rec.Put(hidepidID, k, v); err != nil {
				return err
			}
		}
	}
	if err := env.Rec.Put(hidepidID, "level", level); err != nil {
		return err
	}

	gid, exists := gidOf(ctx, env, group)
	if !exists {
		if _, err := env.Run.Run(ctx, "groupadd", "--system", group); err != nil {
			return fmt.Errorf("cannot create the group %s: %w", group, err)
		}
		createdHere = true
		if err := env.Rec.Put(hidepidID, "group-created", group); err != nil {
			return fail(err)
		}
		if gid, exists = gidOf(ctx, env, group); !exists {
			return fmt.Errorf("created the group %s but cannot read its number", group)
		}
	}
	if err := env.Rec.Put(hidepidID, "group", group); err != nil {
		return err
	}
	added, _, _ := env.Rec.Get(hidepidID, "added")
	addedList := lines(added)
	for _, m := range members {
		if ok, _ := inGroup(env, group, m); ok {
			continue
		}
		if _, err := env.Run.Run(ctx, "usermod", "-aG", group, m); err != nil {
			return fmt.Errorf("cannot add %s to %s: %w", m, group, err)
		}
		if !contains(addedList, m) {
			addedList = append(addedList, m)
		}
	}
	if err := env.Rec.Put(hidepidID, "added", strings.Join(addedList, "\n")); err != nil {
		return err
	}

	c, err := readFstab(env)
	if err != nil {
		return err
	}
	entry := fmt.Sprintf("proc /proc proc defaults,hidepid=%s,gid=%d 0 0", level, gid)
	if err := putFile(env, hidepidID, "/etc/fstab", fstabSet(c, procMount, hidepidID, entry), 0o644); err != nil {
		return fail(err)
	}
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fail(err)
	}
	if out, err := env.Run.Run(ctx, "mount", "-o", fmt.Sprintf("remount,hidepid=%s,gid=%d", level, gid), procMount); err != nil {
		return fail(fmt.Errorf("cannot remount /proc: %w: %s", err, strings.TrimSpace(string(out))))
	}
	env.Log.Infof("ordinary users see only their own processes. Members of %s see all of them", group)
	return nil
}

func (h *procHidepid) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(hidepidID) {
		env.Log.Warnf("%s: no record, leaving /proc alone", hidepidID)
		return nil
	}
	if err := restoreFile(env, hidepidID, "/etc/fstab"); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	prev, _, _ := env.Rec.Get(hidepidID, "prev-hidepid")
	gid, _, _ := env.Rec.Get(hidepidID, "prev-gid")
	if prev == "" {
		prev = "off"
	}
	if gid == "" {
		gid = "0"
	}
	if out, err := env.Run.Run(ctx, "mount", "-o", fmt.Sprintf("remount,hidepid=%s,gid=%s", prev, gid), procMount); err != nil {
		return fmt.Errorf("cannot remount /proc: %w: %s", err, strings.TrimSpace(string(out)))
	}
	group, _, _ := env.Rec.Get(hidepidID, "group")
	if created, _, _ := env.Rec.Get(hidepidID, "group-created"); created != "" && created == group {
		if _, err := env.Run.Run(ctx, "groupdel", group); err != nil {
			env.Log.Warnf("cannot remove the group %s: %v", group, err)
		}
	} else if group != "" {
		added, _, _ := env.Rec.Get(hidepidID, "added")
		for _, m := range lines(added) {
			if _, err := env.Run.Run(ctx, "gpasswd", "-d", m, group); err != nil {
				env.Log.Warnf("cannot remove %s from %s: %v", m, group, err)
			}
		}
	}
	return env.Rec.Delete(hidepidID)
}
