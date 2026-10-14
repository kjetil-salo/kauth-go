package auth

import (
	"net/http"
	"strings"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

// resolveSocialService velger tjenesten for /social-login og /ms-oidc-login.
// Login-siden sender ?service= for tjenesten den ble vist for. Uten den vinner
// host-matchen, og en undertjeneste som deler auth-host med foreldretjenesten
// (uten egen auth_host) ville startet flyten som foreldretjenesten.
//
// ?service= får bare overstyre hosten når tjenesten ikke har egen auth_host,
// eller når den er nettopp denne hosten. En tjeneste med en annen auth_host
// tilhører en annen tenant, og skal ikke kunne startes herfra med dens
// credentials.
func resolveSocialService(reg *service.Registry, r *http.Request) *gen.Service {
	serviceID := r.URL.Query().Get("service")
	if serviceID != "" {
		if svc := reg.Resolve("", serviceID, ""); svc != nil &&
			(svc.AuthHost == nil || *svc.AuthHost == "" || strings.EqualFold(*svc.AuthHost, r.Host)) {
			return svc
		}
	}
	// Avvist eller ukjent ?service= skal ikke få en ny sjanse via nivå 3 i
	// Resolve når hosten ikke matcher noen auth_host.
	return reg.ResolveOrDefault(r.Host, "", "")
}
