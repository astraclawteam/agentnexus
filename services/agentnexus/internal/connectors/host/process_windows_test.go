//go:build windows

package host

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestContainmentJobCarriesResourceLimits proves the Windows Job Object the
// process adapter creates actually carries the active-process (fork-bomb) and
// job-memory (memory-bomb) limits derived from the policy, plus KILL_ON_JOB_CLOSE.
// It queries the job configuration directly — no real bomb is spawned.
func TestContainmentJobCarriesResourceLimits(t *testing.T) {
	const memBytes = 256 * 1024 * 1024
	const pids = 24

	cont, err := newContainment(resourceLimits{memoryBytes: memBytes, pidsLimit: pids})
	if err != nil {
		t.Fatalf("newContainment: %v", err)
	}
	defer cont.release()

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var ret uint32
	if err := windows.QueryInformationJobObject(
		cont.job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		&ret,
	); err != nil {
		t.Fatalf("QueryInformationJobObject: %v", err)
	}

	flags := info.BasicLimitInformation.LimitFlags
	if flags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
		t.Error("job missing JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE")
	}
	if flags&windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS == 0 {
		t.Error("job missing JOB_OBJECT_LIMIT_ACTIVE_PROCESS (fork-bomb containment)")
	}
	if flags&windows.JOB_OBJECT_LIMIT_JOB_MEMORY == 0 {
		t.Error("job missing JOB_OBJECT_LIMIT_JOB_MEMORY (memory-bomb containment)")
	}
	if got := info.BasicLimitInformation.ActiveProcessLimit; got != pids {
		t.Errorf("ActiveProcessLimit = %d, want %d", got, pids)
	}
	if got := info.JobMemoryLimit; got != uintptr(memBytes) {
		t.Errorf("JobMemoryLimit = %d, want %d", got, memBytes)
	}
}
