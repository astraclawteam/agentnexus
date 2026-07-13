//go:build windows

package host

import (
	"errors"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// containment contains a connector process and its entire descendant tree in a
// Windows Job Object. The job is configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
// plus an active-process limit (caps a fork bomb) and a job-memory limit (caps a
// memory bomb), all enforced by Windows during the run. The child is started
// SUSPENDED and assigned to the job before it can execute, so even a connector
// that spawns a grandchild as its first action is contained; terminating or
// closing the job then reaps the whole tree.
type containment struct {
	job  windows.Handle
	proc windows.Handle
}

func newContainment(limits resourceLimits) (*containment, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	// Cap the connector's active process count so a fork bomb is contained by the
	// job during the run, not merely reaped afterward.
	if limits.pidsLimit > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		info.BasicLimitInformation.ActiveProcessLimit = uint32(limits.pidsLimit)
	}
	// Cap total job memory so a memory bomb is contained by the job.
	if limits.memoryBytes > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY
		info.JobMemoryLimit = uintptr(limits.memoryBytes)
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	return &containment{job: job}, nil
}

// prepare starts the child SUSPENDED so it can be assigned to the job before it
// runs. Without this, a non-cooperative connector could spawn a grandchild in
// the window between start and job assignment and escape TerminateJobObject.
func (c *containment) prepare(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
}

// started assigns the suspended child to the job and then resumes it. After this
// returns the connector is running and fully contained.
func (c *containment) started(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	c.proc = h
	if err := windows.AssignProcessToJobObject(c.job, h); err != nil {
		return err
	}
	return resumeProcess(uint32(cmd.Process.Pid))
}

// resumeProcess resumes every thread of a freshly created, suspended process. A
// process created with CREATE_SUSPENDED has exactly one (its primary) thread;
// resuming it lets the process begin executing — now inside the job.
func resumeProcess(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	resumed := 0
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid {
			continue
		}
		thread, terr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if terr != nil {
			continue
		}
		_, _ = windows.ResumeThread(thread)
		_ = windows.CloseHandle(thread)
		resumed++
	}
	if resumed == 0 {
		return errors.New("no thread found to resume for suspended connector process")
	}
	return nil
}

// terminate kills every process in the job. It is idempotent.
func (c *containment) terminate() {
	if c.job != 0 {
		_ = windows.TerminateJobObject(c.job, 1)
	}
}

// release closes the job and process handles. Closing the last job handle also
// enforces KILL_ON_JOB_CLOSE, a second guarantee that no descendant survives.
func (c *containment) release() {
	if c.proc != 0 {
		_ = windows.CloseHandle(c.proc)
		c.proc = 0
	}
	if c.job != 0 {
		_ = windows.CloseHandle(c.job)
		c.job = 0
	}
}

// processAlive reports whether a process with pid currently exists and has not
// exited, by waiting on its handle with a zero timeout.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	event, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return false
	}
	// WAIT_TIMEOUT means the process is still running; WAIT_OBJECT_0 means it has
	// exited (the handle is signaled).
	return event == uint32(windows.WAIT_TIMEOUT)
}
