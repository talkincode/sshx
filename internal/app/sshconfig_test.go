package app

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleSSHConfig = `
# comment
Host *
    ForwardAgent yes
    User default-user

Host web1
    HostName 192.168.1.10
    User root
    Port 2222
    IdentityFile ~/.ssh/id_web
    ProxyJump bastion

Host db1 db2
    HostName=10.0.0.5
    User admin

Host bare-alias

Host web-?
    User ops

Host github.com
    HostName github.com
    IdentityFile ~/.ssh/id_git

Match host prod-*
    User matched

Include ~/.ssh/config.d/*
`

func parseSample(t *testing.T) ([]sshConfigEntry, []string) {
	t.Helper()
	entries, notes, err := parseSSHConfig(strings.NewReader(sampleSSHConfig))
	require.NoError(t, err)
	return entries, notes
}

func TestParseSSHConfig_Entries(t *testing.T) {
	entries, notes := parseSample(t)

	byAlias := map[string]sshConfigEntry{}
	for _, e := range entries {
		byAlias[e.Alias] = e
	}

	web1 := byAlias["web1"]
	assert.Equal(t, "192.168.1.10", web1.HostName)
	assert.Equal(t, "root", web1.User)
	assert.Equal(t, "2222", web1.Port)
	assert.Equal(t, "~/.ssh/id_web", web1.IdentityFile)
	assert.Contains(t, web1.IgnoredOptions, "proxyjump")

	// "Host db1 db2" expands to two entries sharing options, "=" separator works.
	assert.Equal(t, "10.0.0.5", byAlias["db1"].HostName)
	assert.Equal(t, "admin", byAlias["db2"].User)

	// Alias with no HostName is kept; wildcard block options are NOT merged in.
	bare, ok := byAlias["bare-alias"]
	require.True(t, ok)
	assert.Empty(t, bare.HostName)
	assert.Empty(t, bare.User, "Host * options must not pollute concrete entries")

	// Match block options do not leak anywhere.
	for _, e := range entries {
		assert.NotEqual(t, "matched", e.User)
	}

	// Include is reported, not followed.
	require.Len(t, notes, 1)
	assert.Contains(t, notes[0], "Include")
}

func TestBuildImportPlan_PollutionGuards(t *testing.T) {
	entries, _ := parseSample(t)
	settings := &Settings{Hosts: []HostConfig{
		{Name: "web1", Host: "192.168.1.10", Port: "2222"}, // same alias
		{Name: "old-db", Host: "10.0.0.5", Port: "22"},     // same address as db1/db2
	}}

	plan := buildImportPlan(entries, settings)

	candidateNames := make([]string, 0, len(plan.Candidates))
	for _, c := range plan.Candidates {
		candidateNames = append(candidateNames, c.Host.Name)
	}
	// bare-alias and github.com are the only clean imports.
	assert.ElementsMatch(t, []string{"bare-alias", "github.com"}, candidateNames)

	skippedReasons := map[string]string{}
	for _, s := range plan.Skipped {
		skippedReasons[s.Alias] = s.Reason
	}
	assert.Contains(t, skippedReasons["*"], "wildcard")
	assert.Contains(t, skippedReasons["web-?"], "wildcard")
	assert.Contains(t, skippedReasons["web1"], "already exists")
	assert.Contains(t, skippedReasons["db1"], "already configured as 'old-db'")
	assert.Contains(t, skippedReasons["db2"], "already configured as 'old-db'")
}

func TestBuildImportPlan_DuplicateAddressWithinConfig(t *testing.T) {
	entries, _ := parseSample(t)
	plan := buildImportPlan(entries, &Settings{})

	skippedReasons := map[string]string{}
	for _, s := range plan.Skipped {
		skippedReasons[s.Alias] = s.Reason
	}
	// db1 imports first; db2 points at the same address within the same file.
	assert.Contains(t, skippedReasons["db2"], "duplicates ssh_config entry 'db1'")
}

func TestBuildImportPlan_Defaults(t *testing.T) {
	entries, _, err := parseSSHConfig(strings.NewReader("Host solo\n    IdentityFile ~/.ssh/%r_key\n"))
	require.NoError(t, err)

	plan := buildImportPlan(entries, &Settings{})
	require.Len(t, plan.Candidates, 1)

	host := plan.Candidates[0].Host
	assert.Equal(t, "solo", host.Name)
	assert.Equal(t, "solo", host.Host, "alias doubles as address when HostName is absent")
	assert.Equal(t, "22", host.Port)
	assert.Equal(t, DefaultHostType, host.Type)
	assert.Empty(t, host.Key, "IdentityFile with % tokens must not be imported")
	require.Len(t, plan.Notes, 1)
	assert.Contains(t, plan.Notes[0], "%")
}

func TestSelectCandidatesByName(t *testing.T) {
	entries, _ := parseSample(t)
	plan := buildImportPlan(entries, &Settings{})

	selected, err := selectCandidatesByName(plan, "web1, db1")
	require.NoError(t, err)
	require.Len(t, selected, 2)
	assert.Equal(t, "web1", selected[0].Host.Name)
	assert.Equal(t, "db1", selected[1].Host.Name)

	// All-or-nothing: unknown name fails without partial result.
	_, err = selectCandidatesByName(plan, "web1,missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")

	// A skipped alias reports its skip reason.
	planWithExisting := buildImportPlan(entries, &Settings{Hosts: []HostConfig{{Name: "web1", Host: "x"}}})
	_, err = selectCandidatesByName(planWithExisting, "web1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	_, err = selectCandidatesByName(plan, " , ")
	require.Error(t, err)
}

func TestResolveImportSelection(t *testing.T) {
	entries, _ := parseSample(t)
	plan := buildImportPlan(entries, &Settings{})

	all, err := resolveImportSelection(plan, "all\n")
	require.NoError(t, err)
	assert.Len(t, all, len(plan.Candidates))

	byMixed, err := resolveImportSelection(plan, "1, db1\n")
	require.NoError(t, err)
	require.Len(t, byMixed, 2)
	assert.Equal(t, plan.Candidates[0].Host.Name, byMixed[0].Host.Name)
	assert.Equal(t, "db1", byMixed[1].Host.Name)

	// Duplicates collapse.
	dedup, err := resolveImportSelection(plan, "1 1 1\n")
	require.NoError(t, err)
	assert.Len(t, dedup, 1)

	empty, err := resolveImportSelection(plan, "\n")
	require.NoError(t, err)
	assert.Nil(t, empty)

	_, err = resolveImportSelection(plan, "99\n")
	require.Error(t, err)

	_, err = resolveImportSelection(plan, "nope\n")
	require.Error(t, err)
}

func TestParseArgs_HostImportFlags(t *testing.T) {
	config := ParseArgs([]string{"sshx", "--host-import"})
	assert.Equal(t, "host", config.Mode)
	assert.Equal(t, "import", config.HostAction)
	assert.Empty(t, config.HostImportNames)

	config = ParseArgs([]string{"sshx", "--host-import=web1,db1", "--ssh-config=/tmp/config"})
	assert.Equal(t, "host", config.Mode)
	assert.Equal(t, "import", config.HostAction)
	assert.Equal(t, "web1,db1", config.HostImportNames)
	assert.Equal(t, "/tmp/config", config.SSHConfigPath)
}
