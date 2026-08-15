package sshclient

import (
	"strings"
	"testing"
)

func TestValidateCommand_BlocksDirectDBClients(t *testing.T) {
	blocked := []struct {
		name    string
		command string
	}{
		{"plain psql", `psql -U app -d appdb -c "DELETE FROM users"`},
		{"psql interactive", `psql`},
		{"psql full path", `/usr/lib/postgresql/16/bin/psql -c "SELECT 1"`},
		{"pgcli", `pgcli -h localhost appdb`},
		{"env assignment prefix", `PGPASSWORD=secret psql -h 127.0.0.1 -c "TRUNCATE t"`},
		{"sudo -u postgres", `sudo -u postgres psql -d app -c "UPDATE t SET x=1"`},
		{"pipe into psql", `echo "DROP TABLE t;" | psql -U app appdb`},
		{"sh -c wrapper", `sh -c 'psql -U app -c "SELECT 1"'`},
		{"bash -lc wrapper", `bash -lc "psql appdb"`},
		{"su -c", `su postgres -c 'psql -c "SELECT 1"'`},
		{"docker exec", `docker exec tsdb psql -U app -d appdb -c "SELECT count(*) FROM users"`},
		{"docker exec with flags", `docker exec -i -t -u postgres -e PGOPTIONS=-c tsdb psql -c "SELECT 1"`},
		{"docker exec nested shell", `docker exec tsdb sh -c 'psql -U app -c "DELETE FROM x"'`},
		{"podman exec", `podman exec db psql -c "SELECT 1"`},
		{"docker compose exec", `docker compose exec db psql -U app appdb`},
		{"docker run image psql", `docker run --rm postgres:16 psql -h db -c "SELECT 1"`},
		{"kubectl exec dashdash", `kubectl exec -n prod pg-0 -- psql -U app -c "SELECT 1"`},
		{"kubectl exec legacy", `kubectl exec pg-0 psql -c "SELECT 1"`},
		{"command substitution", `echo "$(psql -tA -c 'SELECT 1')"`},
		{"backtick substitution", "echo `psql -tA -c 'SELECT 1'`"},
		{"after semicolon", `uptime; psql -c "SELECT 1"`},
		{"after and-and", `true && psql appdb`},
		{"timeout wrapper", `timeout 30 psql -c "SELECT 1"`},
		{"nohup env chain", `nohup env PGHOST=db psql -c "SELECT 1"`},
		{"exec wrapper", `exec psql appdb`},
		{"command wrapper executes", `command psql appdb`},
		{"multiline script", "set -e\npsql -U app -c \"SELECT 1\"\n"},
		{"heredoc", "psql -U app appdb <<EOF\nSELECT 1;\nEOF"},
		{"plain sqlite3", `sqlite3 /var/lib/app.db "DELETE FROM users"`},
		{"sudo sqlite3", `sudo -u app sqlite3 /data/app.db "SELECT 1"`},
		{"sh -c sqlite3", `sh -c 'sqlite3 /tmp/app.db "SELECT 1"'`},
	}
	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.command)
			if err == nil {
				t.Fatalf("ValidateCommand(%q) expected block, got nil", tt.command)
			}
			if !strings.Contains(err.Error(), "sshx sql") {
				t.Errorf("block message should point to sshx sql, got: %v", err)
			}
		})
	}
}

func TestValidateCommand_AllowsNonExecutionDBReferences(t *testing.T) {
	allowed := []string{
		`which psql`,
		`command -v psql`,
		`psql --version`,
		`psql -V`,
		`sqlite3 --version`,
		`which sqlite3`,
		`psql --help`,
		`docker exec tsdb psql --version`,
		`grep psql /var/log/syslog`,
		`ps aux | grep psql`,
		`echo psql`,
		`cat /etc/passwd`,
		`docker exec tsdb pg_isready -U app`,
		`docker logs tsdb | grep -i psql`,
		`docker ps`,
		`systemctl status postgresql`,
		`ls -la /usr/lib/postgresql/16/bin`,
		`pg_dump -U app appdb`,
		`apt list --installed | grep postgresql`,
		`man psql`,
		`type psql`,
		`kubectl get pods`,
		`kubectl exec pg-0 -- pg_isready`,
		`docker compose ps`,
		`sudo systemctl restart postgresql`,
	}
	for _, cmd := range allowed {
		t.Run(cmd, func(t *testing.T) {
			if err := ValidateCommand(cmd); err != nil {
				t.Errorf("ValidateCommand(%q) should be allowed, got: %v", cmd, err)
			}
		})
	}
}

func TestDetectGuardedDBClient_DepthLimit(t *testing.T) {
	cmd := "psql"
	for i := 0; i < 10; i++ {
		cmd = "sh -c '" + strings.ReplaceAll(cmd, "'", `'\''`) + "'"
	}
	// Deeply nested beyond the limit: detector must terminate without panic.
	_, _, _ = detectGuardedDBClient(cmd, 0)
}

func TestSplitShellSegments(t *testing.T) {
	tests := []struct {
		in   string
		want [][]string
	}{
		{`psql -c "SELECT 1; DROP TABLE x"`, [][]string{{"psql", "-c", "SELECT 1; DROP TABLE x"}}},
		{`a | b; c && d`, [][]string{{"a"}, {"b"}, {"c"}, {"d"}}},
		{`FOO=bar cmd 'quoted arg'`, [][]string{{"FOO=bar", "cmd", "quoted arg"}}},
		{"line1\nline2", [][]string{{"line1"}, {"line2"}}},
	}
	for _, tt := range tests {
		got := splitShellSegments(tt.in)
		if len(got) != len(tt.want) {
			t.Fatalf("splitShellSegments(%q) = %v, want %v", tt.in, got, tt.want)
		}
		for i := range got {
			if strings.Join(got[i], "\x00") != strings.Join(tt.want[i], "\x00") {
				t.Errorf("segment %d of %q = %v, want %v", i, tt.in, got[i], tt.want[i])
			}
		}
	}
}
