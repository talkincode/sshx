package sqlsafe

// streamLockedBackup keeps one client alive (and its transaction/locks held)
// while the host writes the preimage. Mutation SQL is sent only after the
// entire framed backup has been written successfully. Disconnect or write
// failure closes the input without ever sending the mutation.
func streamLockedBackup(client, prelude, mutation, path string, p *Protocol) string {
	return lockedBackup(client, prelude, mutation, path, "", p)
}

func lockedBackup(client, prelude, mutation, path, backupCommand string, p *Protocol) string {
	work := path + ".stream-" + p.Token
	in := maybeQuote(work + "/input")
	out := maybeQuote(work + "/output")
	begin := p.frame("copy", "begin")
	end := p.frame("copy", "end")
	sink := maybeQuote(path)
	afterCopy := ""
	if backupCommand != "" {
		sink = "/dev/null"
		afterCopy = "[ ! -e " + maybeQuote(path) + " ] && [ ! -L " + maybeQuote(path) + " ] && " +
			backupCommand + " || { exec 3>&-; cat <&4 >/dev/null; wait \"$sql_pid\"; exit 1; }; "
	}
	return mkdirPrefix(path) +
		"mkdir " + maybeQuote(work) + " || exit $?; " +
		"cleanup_sqlx_stream() { rm -f " + in + " " + out + "; rmdir " + maybeQuote(work) + "; }; " +
		"trap cleanup_sqlx_stream EXIT; trap 'exit 1' HUP INT TERM; " +
		"mkfifo " + in + " " + out + " || exit $?; " +
		client + " < " + in + " > " + out + " & sql_pid=$!; " +
		"exec 3> " + in + "; exec 4< " + out + "; " +
		"set -C; exec 5> " + sink + " || { exec 3>&-; cat <&4 >/dev/null; wait \"$sql_pid\"; exit 1; }; " +
		"printf '%s' " + shellQuote(prelude) + " >&3 || { exec 5>&-; exec 3>&-; cat <&4 >/dev/null; wait \"$sql_pid\"; exit 1; }; " +
		"copying=0; end_seen=0; backup_failed=0; " +
		"while IFS= read -r line <&4; do " +
		"if [ \"$line\" = " + shellQuote(begin) + " ] && [ \"$copying\" -eq 0 ]; then copying=1; " +
		"elif [ \"$line\" = " + shellQuote(end) + " ] && [ \"$copying\" -eq 1 ]; then end_seen=1; break; " +
		"elif [ \"$copying\" -eq 1 ]; then printf '%s\\n' \"$line\" >&5 || backup_failed=1; " +
		"else printf '%s\\n' \"$line\"; fi; done; exec 5>&-; " +
		"if [ \"$backup_failed\" -ne 0 ] || [ \"$end_seen\" -ne 1 ]; then " +
		"exec 3>&-; cat <&4 >/dev/null; wait \"$sql_pid\"; exit 1; fi; " +
		afterCopy +
		"printf '%s\\n' " + shellQuote(p.frame("backup", "ready")) + "; " +
		"printf '%s' " + shellQuote(mutation) + " >&3 || { exec 3>&-; cat <&4 >/dev/null; wait \"$sql_pid\"; exit 1; }; " +
		"exec 3>&-; cat <&4; output_status=$?; wait \"$sql_pid\"; sql_status=$?; " +
		"if [ \"$sql_status\" -ne 0 ]; then exit \"$sql_status\"; fi; exit \"$output_status\""
}

// lockedSQLiteFileBackup holds BEGIN IMMEDIATE in the mutation client. SQLite's
// backup API cannot read that same connection's active write transaction, so a
// second read-only connection copies the file while the first excludes writers.
func lockedSQLiteFileBackup(client, reader, prelude, mutation, path string, p *Protocol) string {
	return lockedBackup(client, prelude, mutation, path, reader+" "+shellQuote(".backup "+path), p)
}
