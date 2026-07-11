package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestReleaseAuthScriptRejectsUnsafeDSNBeforeAnyHook(t *testing.T) {
	fixture := newReleaseFixture(t)
	invalid := []string{
		"postgres://db.example/agentnexus",
		"postgres://db.example/agentnexus?sslmode=allow",
		"postgres://db.example/agentnexus?sslmode=prefer",
		"postgres://db.example/agentnexus?sslmode=disable",
		"postgres://db.example/agentnexus?sslmode=require&sslmode=verify-full",
		"postgres://db.example/agentnexus?sslmode=%64isable",
		"https://db.example/agentnexus?sslmode=verify-full",
	}
	for _, dsn := range invalid {
		fixture.resetState(t)
		result := fixture.run(t, dsn, 0, 0)
		if result.err == nil || fixture.state(t) != "" || !strings.Contains(result.stderr, "release-preflight:") {
			t.Fatalf("dsn=%q err=%v state=%q stderr=%q", dsn, result.err, fixture.state(t), result.stderr)
		}
	}
}

func TestReleaseAuthScriptUsesIsolatedCutoverAndCompensatesVerificationFailure(t *testing.T) {
	fixture := newReleaseFixture(t)
	t.Run("success opens traffic only after verification", func(t *testing.T) {
		fixture.resetState(t)
		result := fixture.run(t, strongReleaseDSN, 0, 0)
		want := "stop_old\nbackup\nmigrate\nstart_new_isolated\nverify\nopen_traffic\n"
		if result.err != nil || fixture.state(t) != want || fixture.traffic(t) != "open" || strings.Contains(fixture.state(t), "stop_new") {
			t.Fatalf("err=%v state=%q stdout=%q stderr=%q", result.err, fixture.state(t), result.stdout, result.stderr)
		}
		if result.stdout != "release-auth: backup=backup-123\nrelease-auth: traffic opened backup=backup-123\n" {
			t.Fatalf("stdout=%q", result.stdout)
		}
	})

	t.Run("verify failure stops isolated new binary and keeps maintenance", func(t *testing.T) {
		fixture.resetState(t)
		result := fixture.run(t, strongReleaseDSN, 23, 0)
		want := "stop_old\nbackup\nmigrate\nstart_new_isolated\nverify\nstop_new\n"
		if result.err == nil || fixture.state(t) != want || fixture.traffic(t) != "closed" || strings.Contains(fixture.state(t), "open_traffic") {
			t.Fatalf("err=%v state=%q stdout=%q stderr=%q", result.err, fixture.state(t), result.stdout, result.stderr)
		}
		if !strings.Contains(result.stderr, "verification failed; isolated new binary stopped; maintenance remains active") {
			t.Fatalf("stderr=%q", result.stderr)
		}
	})

	t.Run("stop-new failure is a hard critical failure and never opens traffic", func(t *testing.T) {
		fixture.resetState(t)
		result := fixture.run(t, strongReleaseDSN, 23, 29)
		want := "stop_old\nbackup\nmigrate\nstart_new_isolated\nverify\nstop_new\n"
		if result.err == nil || fixture.state(t) != want || fixture.traffic(t) != "closed" || strings.Contains(fixture.state(t), "open_traffic") {
			t.Fatalf("err=%v state=%q stdout=%q stderr=%q", result.err, fixture.state(t), result.stdout, result.stderr)
		}
		if !strings.Contains(result.stderr, "CRITICAL: verification failed and STOP_NEW failed; maintenance must remain active") {
			t.Fatalf("stderr=%q", result.stderr)
		}
	})
}

const strongReleaseDSN = "postgres://runtime:secret@db.example:5432/agentnexus?sslmode=verify-full"

type releaseFixture struct {
	bash, root, temp, preflight, statePath, trafficPath string
	scriptBash, preflightBash, stateBash, trafficBash   string
	hooks, hooksBash                                    map[string]string
}

type releaseResult struct {
	stdout, stderr string
	err            error
}

func newReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal("bash is required for release contract tests:", err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	preflight := filepath.Join(temp, "release-preflight")
	if runtime.GOOS == "windows" {
		preflight += ".exe"
	}
	build := exec.Command("go", "build", "-buildvcs=false", "-o", preflight, "./cmd/release-preflight")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build preflight: %v: %s", err, output)
	}
	fixture := &releaseFixture{bash: bash, root: root, temp: temp, preflight: preflight, statePath: filepath.Join(temp, "state.log"), trafficPath: filepath.Join(temp, "traffic.state"), hooks: map[string]string{}, hooksBash: map[string]string{}}
	for _, phase := range []string{"stop_old", "backup", "migrate", "start_new_isolated", "verify", "stop_new", "open_traffic"} {
		path := filepath.Join(temp, phase+".sh")
		body := "#!/bin/sh\nprintf '" + phase + "\\n' >> \"$STATE_FILE\"\n"
		if phase == "backup" {
			body += "printf 'backup-123\\n'\n"
		}
		if phase == "stop_old" {
			body += "printf 'closed' > \"$TRAFFIC_FILE\"\n"
		}
		if phase == "open_traffic" {
			body += "printf 'open' > \"$TRAFFIC_FILE\"\n"
		}
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		fixture.hooks[phase] = path
	}
	fixture.scriptBash = bashPath(t, bash, filepath.Join(root, "deploy", "release-auth.sh"))
	fixture.preflightBash = bashPath(t, bash, preflight)
	fixture.stateBash = bashPath(t, bash, fixture.statePath)
	fixture.trafficBash = bashPath(t, bash, fixture.trafficPath)
	for phase, path := range fixture.hooks {
		fixture.hooksBash[phase] = bashPath(t, bash, path)
	}
	return fixture
}

func (f *releaseFixture) run(t *testing.T, dsn string, verifyExit, stopNewExit int) releaseResult {
	t.Helper()
	f.setHookExit(t, "verify", verifyExit)
	f.setHookExit(t, "stop_new", stopNewExit)
	command := exec.Command(f.bash, f.scriptBash)
	command.Env = append(os.Environ(),
		"AGENTNEXUS_MAINTENANCE_ACK=STOP_WRITES_AND_NO_OVERLAP",
		"AGENTNEXUS_POSTGRES_DSN="+dsn,
		"AGENTNEXUS_RELEASE_PREFLIGHT_BIN="+f.preflightBash,
		"AGENTNEXUS_RELEASE_STOP_OLD_HOOK="+f.hooksBash["stop_old"],
		"AGENTNEXUS_RELEASE_BACKUP_HOOK="+f.hooksBash["backup"],
		"AGENTNEXUS_RELEASE_MIGRATE_HOOK="+f.hooksBash["migrate"],
		"AGENTNEXUS_RELEASE_START_NEW_ISOLATED_HOOK="+f.hooksBash["start_new_isolated"],
		"AGENTNEXUS_RELEASE_VERIFY_HOOK="+f.hooksBash["verify"],
		"AGENTNEXUS_RELEASE_STOP_NEW_HOOK="+f.hooksBash["stop_new"],
		"AGENTNEXUS_RELEASE_OPEN_TRAFFIC_HOOK="+f.hooksBash["open_traffic"],
		"STATE_FILE="+f.stateBash,
		"TRAFFIC_FILE="+f.trafficBash,
	)
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return releaseResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func (f *releaseFixture) traffic(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(f.trafficPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (f *releaseFixture) setHookExit(t *testing.T, phase string, code int) {
	t.Helper()
	path := f.hooks[phase]
	body := "#!/bin/sh\nprintf '" + phase + "\\n' >> \"$STATE_FILE\"\n"
	if code != 0 {
		body += "exit " + strconv.Itoa(code) + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (f *releaseFixture) resetState(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(f.statePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.trafficPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *releaseFixture) state(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(f.statePath)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func bashPath(t *testing.T, bash, path string) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return path
	}
	command := exec.Command(bash, "-lc", `cygpath -u "$1"`, "cygpath", path)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("cygpath %s: %v", path, err)
	}
	return strings.TrimSpace(string(output))
}
