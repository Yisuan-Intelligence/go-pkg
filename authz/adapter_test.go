package authz

import (
	"errors"
	"testing"

	"github.com/casbin/casbin/v3/model"
)

func TestSnapshotAdapterRejectsAllWrites(t *testing.T) {
	a := &snapshotAdapter{}
	for _, err := range []error{
		a.SavePolicy(model.NewModel()), a.AddPolicy("p", "p", []string{"subject"}),
		a.RemovePolicy("p", "p", []string{"subject"}), a.RemoveFilteredPolicy("p", "p", 0, "subject"),
	} {
		if !errors.Is(err, ErrReadOnly) {
			t.Fatal("snapshot adapter accepted policy mutation")
		}
	}
}
