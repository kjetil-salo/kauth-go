package service

import (
	"github.com/stretchr/testify/assert"
	"github.com/zral/kauth-go/internal/db/gen"
	"testing"
)

func strPtr(s string) *string { return &s }

func testRegistry(services []gen.Service) *Registry {
	r := &Registry{}
	r.cache = services
	return r
}

func TestResolve_ByAuthHost(t *testing.T) {
	reg := testRegistry([]gen.Service{
		{ID: "spekto", Domain: "spekto.live", AuthHost: strPtr("auth.spekto.live")},
		{ID: "klarsyn", Domain: "klarsyn.net", IsDefault: 1},
	})
	svc := reg.Resolve("auth.spekto.live", "", "")
	assert.Equal(t, "spekto", svc.ID)
}

func TestResolve_ByServiceID(t *testing.T) {
	reg := testRegistry([]gen.Service{
		{ID: "spekto", Domain: "spekto.live"},
	})
	svc := reg.Resolve("", "spekto", "")
	assert.Equal(t, "spekto", svc.ID)
}

func TestResolve_ByRedirectURI_LongestMatch(t *testing.T) {
	reg := testRegistry([]gen.Service{
		{ID: "spekto", Domain: "spekto.live"},
		{ID: "wire", Domain: "wire.spekto.live"},
	})
	svc := reg.Resolve("", "", "https://wire.spekto.live/callback")
	assert.Equal(t, "wire", svc.ID)
}

func TestResolve_NoMatch_ReturnsNil(t *testing.T) {
	reg := testRegistry([]gen.Service{
		{ID: "klarsyn", Domain: "klarsyn.net"},
	})
	svc := reg.Resolve("unknown.com", "", "")
	assert.Nil(t, svc)
}

func TestDefault_ReturnsIsDefault(t *testing.T) {
	reg := testRegistry([]gen.Service{
		{ID: "a", Domain: "a.com", IsDefault: 0},
		{ID: "b", Domain: "b.com", IsDefault: 1},
	})
	assert.Equal(t, "b", reg.Default().ID)
}

func TestIsAllowedCallback(t *testing.T) {
	reg := &Registry{}
	svc := &gen.Service{CallbackUrl: "https://app.spekto.live/cb,https://test.spekto.live/cb"}
	assert.True(t, reg.IsAllowedCallback(svc, "https://app.spekto.live/cb"))
	assert.False(t, reg.IsAllowedCallback(svc, "https://evil.com/cb"))
}
