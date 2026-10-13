package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/zral/kauth-go/internal/admin"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/jobs"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

func main() {
	// ── 1. Last konfigurasjon ────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("konfigurasjonsfeil: %v", err)
	}

	// ── Logging ──────────────────────────────────────────────────────────────
	level := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	// ── 2. Åpne database, kjør migrasjoner ──────────────────────────────────
	sqlDB, queries, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer sqlDB.Close()

	// ── 3. Initialiser støttetjenester ──────────────────────────────────────
	auditSvc := audit.NewService(queries)
	// mail.New tar config.Config (verdi, ikke peker)
	mailSvc := mail.New(*cfg)

	// ── 4. Varm opp ServiceRegistry ─────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	registry := service.NewRegistry(queries)
	if err := registry.Warmup(ctx); err != nil {
		log.Fatalf("serviceregistry warmup: %v", err)
	}
	log.Println("serviceregistry: cache varmet opp")

	// ── 5. Initialiser token-laget ───────────────────────────────────────────
	issuer, err := token.NewIssuer(cfg.PrivateKey, cfg.PublicKey, cfg.Issuer, cfg.AccessTokenTTL, cfg.AdminTokenTTL)
	if err != nil {
		log.Fatalf("token issuer: %v", err)
	}
	refreshSvc := token.NewRefreshService(queries, auditSvc)

	// ── 6. Parse HTML-maler ──────────────────────────────────────────────────
	tmpl := template.Must(template.ParseGlob("templates/*.html"))

	// ── 7. Initialiser auth-handlers ─────────────────────────────────────────
	loginH := &auth.LoginHandler{Registry: registry, Templates: tmpl}
	magicH := auth.NewMagicHandlers(*cfg, queries, mailSvc, issuer, refreshSvc, registry, auditSvc, tmpl)
	googleH := auth.NewGoogleHandlers(*cfg, queries, issuer, refreshSvc, registry, auditSvc)
	msH := auth.NewMicrosoftHandlers(*cfg, queries, issuer, refreshSvc, registry, auditSvc)
	passwordH := auth.NewPasswordHandlers(queries, issuer, refreshSvc, registry, auditSvc)
	dispatchH := &auth.DispatchHandler{Registry: registry, Issuer: issuer, Queries: queries, DefaultSvcID: ""}
	meH := &auth.MeHandler{Issuer: issuer, CookieName: "auth_token"}

	// ── 8. Initialiser admin-handlers ────────────────────────────────────────
	// cfg er allerede *config.Config — ingen & nødvendig
	adminAuthH := admin.NewAuthHandler(queries, issuer, mailSvc, auditSvc, cfg)
	adminUsersH := admin.NewUsersHandler(queries, auditSvc)
	adminAuditH := admin.NewAuditHandler(sqlDB)
	adminSvcsH := admin.NewServicesHandler(queries, registry, auditSvc)

	// ── 9. Start bakgrunnsjobber ─────────────────────────────────────────────
	go jobs.NewCleanup(queries).Run(ctx)
	log.Println("bakgrunnsjobber: cleanup startet")

	// ── 10. Bygg Chi-router ───────────────────────────────────────────────────
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(auth.ClientIPMiddleware)

	// Statiske filer
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// ── Legacy-redirects ──────────────────────────────────────────────────────
	r.Get("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusMovedPermanently)
	})
	r.Get("/login-pov.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusMovedPermanently)
	})

	// ── Login-side ────────────────────────────────────────────────────────────
	r.Get("/login", loginH.ServeLogin)

	// ── Passord-login ─────────────────────────────────────────────────────────
	r.Post("/do-login", passwordH.DoLogin)

	// ── Google OIDC ───────────────────────────────────────────────────────────
	r.Get("/oidc-login", googleH.InitiateLogin)
	r.Get("/social-login", googleH.InitiateLogin) // alias matchende Java-URL
	r.Get("/callback", googleH.HandleCallback)

	// ── Microsoft OIDC ────────────────────────────────────────────────────────
	r.Get("/ms-oidc-login", msH.InitiateLogin)
		r.Get("/ms-social-login", msH.InitiateLogin)
	r.Get("/ms-callback", msH.HandleCallback)

	// ── Magic link ────────────────────────────────────────────────────────────
	r.Get("/magic-login", magicH.ShowForm)
	r.Post("/magic-login", magicH.RequestLink)
	r.Get("/magic-login/{token}", magicH.VerifyToken)

	// ── Token-endepunkt: refresh_token + authorization_code — CORS kun her ───
	r.With(auth.CORSMiddleware(cfg.CORSOrigins)).Post("/token", passwordH.Token)

	// ── Post-login routing ────────────────────────────────────────────────────
	r.Get("/dispatch", dispatchH.ServeDispatch)

	// ── Logout ────────────────────────────────────────────────────────────────
	r.Get("/logout", dispatchH.ServeLogout)

	// ── Bruker-info — JWT-auth håndteres internt i ServeMe ───────────────────
	r.Get("/api/me", meH.ServeMe)

	// ── JWKS + OpenID Discovery — CORS kun her ────────────────────────────────
	r.Route("/.well-known", func(r chi.Router) {
		r.Use(auth.CORSMiddleware(cfg.CORSOrigins))
		r.Get("/jwks.json", issuer.JWKSHandler)
		r.Get("/openid-configuration", issuer.DiscoveryHandler())
	})

	// ── Admin-panel ───────────────────────────────────────────────────────────
	r.Route("/admin", func(r chi.Router) {
		// Åpne admin-ruter (ingen auth-middleware)
		r.Get("/login", adminAuthH.HandleLoginGet)
		r.Post("/login", adminAuthH.HandleLoginPost)
		r.Get("/verify", adminAuthH.HandleVerify)
		r.Get("/logout", adminAuthH.HandleLogout)
		r.Get("/google-init", adminAuthH.HandleGoogleInitiate)
		r.Get("/google-callback", adminAuthH.HandleGoogleCallback)

		// Beskyttede admin-ruter
		r.Group(func(r chi.Router) {
			r.Use(admin.AdminAuthMiddleware(issuer))

			// Root redirect
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/admin/users", http.StatusFound)
			})

			// Brukerhåndtering
			r.Get("/users", adminUsersH.HandleList)
			r.Get("/users/new", adminUsersH.HandleNew)
			r.Post("/users", adminUsersH.HandleCreate)
			r.Get("/users/{id}/edit", adminUsersH.HandleEdit)
			r.Post("/users/{id}", adminUsersH.HandleUpdate)
			r.Post("/users/{id}/deactivate", adminUsersH.HandleDeactivate)
			r.Get("/users/export", adminUsersH.HandleExport)

			// Audit-logg
			r.Get("/audit", adminAuditH.HandleList)
			r.Get("/audit/export", adminAuditH.HandleExport)

			// Tjenestehåndtering
			r.Get("/services", adminSvcsH.HandleList)
			r.Get("/services/new", adminSvcsH.HandleNew)
			r.Post("/services", adminSvcsH.HandleCreate)
			r.Get("/services/{id}/edit", adminSvcsH.HandleEdit)
			r.Post("/services/{id}", adminSvcsH.HandleUpdate)
		})
	})

	// ── 11. Start HTTP-server med graceful shutdown ───────────────────────────
	srv := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("kauth lytter på :%s (issuer: %s)\n", cfg.HTTPPort, cfg.Issuer)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		log.Println("kauth: mottok avslutningssignal")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown feilet: %v", err)
		}
		log.Println("kauth: avsluttet rent")
	case err := <-errCh:
		if err != nil {
			log.Fatalf("server-feil: %v", err)
		}
	}
}
