package domain_test

import (
	"reflect"
	"testing"

	"github.com/zhuhaoyu/kavern/internal/domain"
)

func TestDomainHierarchy(t *testing.T) {
	user := domain.User{ID: "user-1", Name: "owner"}
	project := domain.Project{ID: "project-1", UserID: user.ID, Name: "project"}
	device := domain.Device{ID: "device-1", ProjectID: project.ID, Name: "device", Enabled: true}
	tunnel := domain.Tunnel{ID: "tunnel-1", DeviceID: device.ID, Protocol: domain.TunnelProtocolTCP, Enabled: true}

	if project.UserID != user.ID {
		t.Fatalf("project does not belong to user")
	}
	if device.ProjectID != project.ID {
		t.Fatalf("device does not belong to project")
	}
	if tunnel.DeviceID != device.ID {
		t.Fatalf("tunnel does not belong to device")
	}
}

func TestUserDoesNotContainVKey(t *testing.T) {
	userType := reflect.TypeOf(domain.User{})
	if _, ok := userType.FieldByName("VKey"); ok {
		t.Fatalf("vkey must not belong to User")
	}
}
