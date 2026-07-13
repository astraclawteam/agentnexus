package evidence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// ErrObjectNotFound marks a missing staged object.
var ErrObjectNotFound = errors.New("staged object not found")

// ObjectStore stages encrypted evidence content under opaque object keys.
// The store receives CIPHERTEXT ONLY: the service seals content before any
// byte reaches an implementation, so no store ever observes plaintext.
type ObjectStore interface {
	Put(ctx context.Context, key string, ciphertext []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

// objectKeyRe pins object keys to the opaque service-minted shape. It is the
// structural path-traversal guard of every implementation.
var objectKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,200}$`)

func validObjectKey(key string) error {
	if !objectKeyRe.MatchString(key) {
		return fmt.Errorf("%w: object key is not an opaque store key", ErrInvalidRequest)
	}
	return nil
}

// MemoryObjectStore is the in-memory ObjectStore used by unit tests and
// harnesses.
type MemoryObjectStore struct {
	mu      sync.RWMutex
	objects map[string][]byte
}

func NewMemoryObjectStore() *MemoryObjectStore {
	return &MemoryObjectStore{objects: map[string][]byte{}}
}

func (s *MemoryObjectStore) Put(_ context.Context, key string, ciphertext []byte) error {
	if err := validObjectKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = append([]byte(nil), ciphertext...)
	return nil
}

func (s *MemoryObjectStore) Get(_ context.Context, key string) ([]byte, error) {
	if err := validObjectKey(key); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	blob, ok := s.objects[key]
	if !ok {
		return nil, ErrObjectNotFound
	}
	return append([]byte(nil), blob...), nil
}

func (s *MemoryObjectStore) Delete(_ context.Context, key string) error {
	if err := validObjectKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, key)
	return nil
}

// Objects returns a snapshot of every stored blob (test observability only).
func (s *MemoryObjectStore) Objects() map[string][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]byte, len(s.objects))
	for key, blob := range s.objects {
		out[key] = append([]byte(nil), blob...)
	}
	return out
}

// FileObjectStore is the durable filesystem-rooted ObjectStore of this task's
// single-node deployment form. Writes are atomic (temp file + rename inside
// the root) and keys are structurally traversal-safe.
type FileObjectStore struct {
	root string
}

// NewFileObjectStore roots a store at dir, creating it when absent.
func NewFileObjectStore(root string) (*FileObjectStore, error) {
	if root == "" {
		return nil, errors.New("file object store requires a root directory")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	return &FileObjectStore{root: absolute}, nil
}

func (s *FileObjectStore) path(key string) (string, error) {
	if s == nil || s.root == "" {
		return "", ErrUnavailable
	}
	if err := validObjectKey(key); err != nil {
		return "", err
	}
	return filepath.Join(s.root, key+".enc"), nil
}

func (s *FileObjectStore) Put(_ context.Context, key string, ciphertext []byte) error {
	target, err := s.path(key)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(s.root, "staging-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	if _, err := temp.Write(ciphertext); err != nil {
		_ = temp.Close()
		_ = os.Remove(tempName)
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		_ = os.Remove(tempName)
		return err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	// Keys are unique per staged object; a leftover from a crashed prior
	// attempt is removed so the rename lands atomically on Windows too.
	_ = os.Remove(target)
	if err := os.Rename(tempName, target); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	return nil
}

func (s *FileObjectStore) Get(_ context.Context, key string) ([]byte, error) {
	target, err := s.path(key)
	if err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrObjectNotFound
		}
		return nil, err
	}
	return blob, nil
}

func (s *FileObjectStore) Delete(_ context.Context, key string) error {
	target, err := s.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
