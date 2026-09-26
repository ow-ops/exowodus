// Command exodus migrates Matrix accounts to Continuwuity.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"

	"exodus/internal/archive"
	"exodus/internal/migrate"
	"exodus/internal/mx"
	"exodus/internal/proxy"
	"exodus/internal/relay"
)

const impersonationTTL = 24 * time.Hour

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := newRootCmd().ExecuteContext(ctx)
	stop()
	if err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var verbose bool
	root := &cobra.Command{
		Use:   "exodus",
		Short: "Migrate Matrix accounts from Synapse to Continuwuity",
		Long: `exodus copies accounts, profiles, media, account data, push rules and room
memberships from a Synapse homeserver (or any homeserver, such as matrix.org,
through the client API) to a Continuwuity homeserver.

Moving to a new server name, with the source still online:
  exodus migrate --from https://matrix.org --from-token ... --to https://new.example --registration-token ...

Replacing Synapse on the same server name:
  exodus export --from https://example.com --from-admin-token ... --all-users
  (stop Synapse, start Continuwuity on the same server name)
  exodus import --to https://example.com --registration-token ...`,
		SilenceUsage: true,
		PersistentPreRun: func(*cobra.Command, []string) {
			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")
	root.AddCommand(newExportCmd(), newImportCmd(), newMigrateCmd(), newProxyCmd(), newLinkSSOCmd())
	return root
}

type sourceFlags struct {
	url, token, user, password, adminToken, db string
	signingKey                                 string
	masURL, masToken, masDB                    string
	users                                      []string
	allUsers                                   bool
}

func (f *sourceFlags) register(cmd *cobra.Command) {
	fs := cmd.Flags()
	fs.StringVar(&f.url, "from", "", "source homeserver client API URL")
	fs.StringVar(&f.token, "from-token", os.Getenv("EXODUS_FROM_TOKEN"), "source access token of the user to migrate [$EXODUS_FROM_TOKEN]")
	fs.StringVar(&f.user, "from-user", "", "source user to log in as (with --from-password)")
	fs.StringVar(&f.password, "from-password", os.Getenv("EXODUS_FROM_PASSWORD"), "source password [$EXODUS_FROM_PASSWORD]")
	fs.StringVar(&f.adminToken, "from-admin-token", os.Getenv("EXODUS_FROM_ADMIN_TOKEN"), "Synapse admin access token, to migrate several users [$EXODUS_FROM_ADMIN_TOKEN]")
	fs.StringSliceVar(&f.users, "users", nil, "user IDs to migrate (with --from-admin-token)")
	fs.BoolVar(&f.allUsers, "all-users", false, "migrate every local account (with --from-admin-token)")
	fs.StringVar(&f.masURL, "from-mas-url", "", "Matrix Authentication Service URL, when Synapse delegates authentication to it")
	fs.StringVar(&f.masToken, "from-mas-token", os.Getenv("EXODUS_FROM_MAS_TOKEN"), "MAS admin API token (urn:mas:admin scope) [$EXODUS_FROM_MAS_TOKEN]")
	fs.StringVar(&f.masDB, "mas-db", os.Getenv("EXODUS_MAS_DB"), "MAS database (postgres:// DSN), to keep passwords and legacy client sessions [$EXODUS_MAS_DB]")
	fs.StringVar(&f.db, "synapse-db", os.Getenv("EXODUS_SYNAPSE_DB"), "Synapse database (postgres:// DSN or SQLite path), to keep passwords and client sessions [$EXODUS_SYNAPSE_DB]")
	_ = cmd.MarkFlagRequired("from")
	cmd.MarkFlagsMutuallyExclusive("from-token", "from-user", "from-admin-token")
	cmd.MarkFlagsMutuallyExclusive("users", "all-users")
}

type source struct {
	db         *migrate.SynapseDB
	mas        *migrate.MAS
	masDB      *migrate.MASDB
	serverName string
	admin      *mautrix.Client
	adminID    string
	users      []migrate.SynapseUser
	// deactivated accounts cannot be logged into and are exported apart.
	deactivated []migrate.SynapseUser
	single      *migrate.Session
}

func (f *sourceFlags) open(ctx context.Context) (*source, error) {
	s, err := f.openAPI(ctx)
	if err != nil {
		return nil, err
	}
	if f.masURL != "" {
		if f.adminToken == "" || f.masToken == "" {
			return nil, errors.New("--from-mas-url requires --from-admin-token and --from-mas-token")
		}
		if s.mas, err = migrate.NewMAS(f.masURL, f.masToken); err != nil {
			return nil, err
		}
	}
	if f.masDB != "" {
		if s.masDB, err = migrate.OpenMASDB(ctx, f.masDB); err != nil {
			return nil, err
		}
	}
	if f.db == "" {
		return s, nil
	}
	s.db, err = migrate.OpenSynapseDB(ctx, f.db)
	return s, err
}

func (f *sourceFlags) openAPI(ctx context.Context) (*source, error) {
	base, err := mx.New(f.url, "")
	if err != nil {
		return nil, fmt.Errorf("--from: %w", err)
	}
	if f.adminToken == "" && (len(f.users) > 0 || f.allUsers) {
		return nil, errors.New("--users and --all-users require --from-admin-token")
	}
	switch {
	case f.adminToken != "":
		if len(f.users) == 0 && !f.allUsers {
			return nil, errors.New("--from-admin-token requires --users or --all-users")
		}
		admin, err := whoami(ctx, mx.WithToken(base, f.adminToken))
		if err != nil {
			return nil, fmt.Errorf("source: %w", err)
		}
		users, err := migrate.SelectSynapseUsers(ctx, admin, f.users)
		if err != nil {
			return nil, err
		}
		s := &source{serverName: admin.UserID.Homeserver(), admin: admin, adminID: string(admin.UserID)}
		for _, u := range users {
			if u.Deactivated {
				s.deactivated = append(s.deactivated, u)
			} else {
				s.users = append(s.users, u)
			}
		}
		return s, nil
	case f.token != "":
		c, err := whoami(ctx, mx.WithToken(base, f.token))
		if err != nil {
			return nil, fmt.Errorf("source: %w", err)
		}
		return &source{serverName: c.UserID.Homeserver(), single: &migrate.Session{UserID: string(c.UserID), Client: c}}, nil
	case f.user != "":
		if f.password == "" {
			return nil, errors.New("--from-user requires --from-password")
		}
		c, err := mx.Login(ctx, base, f.user, f.password)
		if err != nil {
			return nil, fmt.Errorf("source login: %w", err)
		}
		return &source{serverName: c.UserID.Homeserver(), single: migrate.NewEphemeralSession(string(c.UserID), c)}, nil
	}
	return nil, errors.New("one of --from-token, --from-user or --from-admin-token is required")
}

func whoami(ctx context.Context, c *mautrix.Client) (*mautrix.Client, error) {
	who, err := c.Whoami(ctx)
	if err != nil {
		return nil, err
	}
	c.UserID, c.DeviceID = who.UserID, who.DeviceID
	return c, nil
}

func (s *source) userIDs() map[string]bool {
	ids := map[string]bool{}
	if s.single != nil {
		ids[s.single.UserID] = true
	}
	for _, u := range slices.Concat(s.users, s.deactivated) {
		ids[u.UserID] = true
	}
	return ids
}

// each runs fn per user, continuing past failures.
func (s *source) each(ctx context.Context, fn func(*migrate.Session) error) error {
	if s.single != nil {
		err := fn(s.single)
		s.single.Close(context.WithoutCancel(ctx))
		return err
	}
	var failed int
	for _, u := range s.users {
		sess, relock, err := s.open(ctx, u)
		if err != nil {
			slog.Error("skipping user", "user", u.UserID, "err", err)
			failed++
			continue
		}
		err = fn(sess)
		relock()
		sess.Close(context.WithoutCancel(ctx))
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			slog.Error("user failed", "user", sess.UserID, "err", err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d users failed", failed, len(s.users))
	}
	return nil
}

// open unlocks a locked account until relock.
func (s *source) open(ctx context.Context, u migrate.SynapseUser) (*migrate.Session, func(), error) {
	var sess *migrate.Session
	var err error
	switch {
	case s.mas != nil:
		sess, err = s.mas.Impersonate(ctx, s.admin, u, impersonationTTL)
	case u.UserID == s.adminID:
		// Synapse refuses to impersonate the calling admin.
		sess = &migrate.Session{UserID: s.adminID, Client: s.admin, Admin: u.Admin}
	default:
		sess, err = migrate.Impersonate(ctx, s.admin, u, impersonationTTL)
	}
	if err != nil {
		return nil, nil, err
	}
	if !u.Locked {
		return sess, func() {}, nil
	}
	var relock func()
	if s.mas != nil {
		relock, err = s.mas.UnlockTemporarily(ctx, u.UserID)
	} else {
		relock, err = migrate.UnlockTemporarily(ctx, s.admin, u.UserID)
	}
	if err != nil {
		sess.Close(context.WithoutCancel(ctx))
		return nil, nil, err
	}
	return sess, relock, nil
}

func (s *source) exporter(a *archive.Archive) *migrate.Exporter {
	return &migrate.Exporter{Archive: a, Admin: s.admin, DB: s.db, MAS: s.mas, MASDB: s.masDB}
}

func (s *source) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
	if s.masDB != nil {
		_ = s.masDB.Close()
	}
}

type destFlags struct {
	url, token, password, regToken, adminToken string
	bridges                                    []string
}

type relayFlags struct {
	name, listen, cert, key string
}

func (f *destFlags) register(cmd *cobra.Command) {
	fs := cmd.Flags()
	fs.StringVar(&f.url, "to", "", "Continuwuity client API URL")
	fs.StringVar(&f.token, "to-token", os.Getenv("EXODUS_TO_TOKEN"), "access token of an existing destination account (single user only) [$EXODUS_TO_TOKEN]")
	fs.StringVar(&f.password, "to-password", os.Getenv("EXODUS_TO_PASSWORD"), "password for the destination account (single user only) [$EXODUS_TO_PASSWORD]")
	fs.StringVar(&f.regToken, "registration-token", os.Getenv("EXODUS_REGISTRATION_TOKEN"), "Continuwuity registration token used to create accounts [$EXODUS_REGISTRATION_TOKEN]")
	fs.StringVar(&f.adminToken, "to-admin-token", os.Getenv("EXODUS_TO_ADMIN_TOKEN"), "access token of a Continuwuity server admin, to restore admin rights and recreate local-only rooms [$EXODUS_TO_ADMIN_TOKEN]")
	fs.StringSliceVar(&f.bridges, "appservice-registration", nil, "registration YAML of a source appservice (bridge) to move along, same server name only (repeatable)")
	_ = cmd.MarkFlagRequired("to")
	cmd.MarkFlagsMutuallyExclusive("to-token", "to-password")
}

func (f *destFlags) importer(ctx context.Context, a *archive.Archive, migrated map[string]bool) (*migrate.Importer, error) {
	if (f.token != "" || f.password != "") && len(migrated) != 1 {
		return nil, errors.New("--to-token and --to-password can only be used when migrating a single user")
	}
	dest, err := mx.New(f.url, "")
	if err != nil {
		return nil, fmt.Errorf("--to: %w", err)
	}
	im := &migrate.Importer{
		Archive:           a,
		Dest:              dest,
		DestToken:         f.token,
		DestPassword:      f.password,
		RegistrationToken: f.regToken,
		Migrated:          migrated,
	}
	if f.adminToken != "" {
		if im.Admin, err = migrate.NewContinuwuityAdmin(ctx, mx.WithToken(im.Dest, f.adminToken)); err != nil {
			return nil, err
		}
	}
	if len(f.bridges) > 0 && im.Admin == nil {
		return nil, errors.New("--appservice-registration requires --to-admin-token")
	}
	for _, path := range f.bridges {
		b, err := migrate.LoadBridge(path, im.Dest)
		if err != nil {
			return nil, err
		}
		if err := b.Register(ctx, im.Admin); err != nil {
			return nil, fmt.Errorf("register appservice %s: %w", b.ID, err)
		}
		im.Bridges = append(im.Bridges, b)
	}
	return im, nil
}

func newExportCmd() *cobra.Command {
	var src sourceFlags
	var dir string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export accounts from the source homeserver into an archive",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			s, err := src.open(ctx)
			if err != nil {
				return err
			}
			defer s.Close()
			a, err := archive.Create(dir, s.serverName)
			if err != nil {
				return err
			}
			exp := s.exporter(a)
			var users []*archive.User
			err = s.each(ctx, func(sess *migrate.Session) error {
				u, err := exp.ExportUser(ctx, sess)
				if err != nil {
					return err
				}
				users = append(users, u)
				if s.admin == nil {
					// Without admin access, rooms are exported as their member.
					return exportRooms(ctx, exp, users, sess.Client)
				}
				return nil
			})
			if ctx.Err() != nil {
				return ctx.Err()
			}
			for _, d := range s.deactivated {
				_, derr := exp.ExportDeactivated(d.UserID)
				err = errors.Join(err, derr)
			}
			if s.admin != nil {
				err = errors.Join(err, exportRooms(ctx, exp, users, nil))
			}
			if src.signingKey != "" {
				err = errors.Join(err, exp.ExportRelayKeys(ctx, src.signingKey))
			}
			return errors.Join(err, exp.ExportServer(ctx))
		},
	}
	src.register(cmd)
	cmd.Flags().StringVar(&src.signingKey, "synapse-signing-key", "", "Synapse signing key file: with --synapse-db, rooms only your server was in move with their original events")
	cmd.Flags().StringVar(&dir, "archive", "exodus-archive", "archive directory")
	return cmd
}

func newImportCmd() *cobra.Command {
	var dst destFlags
	var relayOpts relayFlags
	var dir string
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import an archive into Continuwuity",
		Long: `Import an archive into Continuwuity. The source server is not contacted, so
rooms are rejoined through the other servers participating in them. Use this
after replacing Synapse with Continuwuity on the same server name.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			users, err := a.Users()
			if err != nil {
				return err
			}
			migrated := map[string]bool{}
			for _, u := range users {
				migrated[u.UserID] = true
			}
			rooms, err := a.Rooms()
			if err != nil {
				return err
			}
			im, err := dst.importer(ctx, a, migrated)
			if err != nil {
				return err
			}
			srv, err := a.ReadServer()
			if err != nil {
				return err
			}
			if im.Admin != nil && needsAppservice(users, rooms, srv) {
				unregister, err := registerAppservice(ctx, im)
				if err != nil {
					return err
				}
				defer unregister()
			}

			defer im.Close(context.WithoutCancel(ctx))
			var jobs []*migrate.UserJob
			var failed int
			for _, u := range users {
				job, err := im.PrepareUser(ctx, u)
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if err != nil {
					slog.Error("user failed", "user", u.UserID, "err", err)
					failed++
					continue
				}
				jobs = append(jobs, job)
			}
			var roomReports []*migrate.RoomReport
			if len(rooms) > 0 && relayOpts.name != "" {
				rl, err := startRelay(ctx, a, dst.url, relayOpts, im)
				if err != nil {
					return err
				}
				defer func() { _ = rl.Stop(context.WithoutCancel(ctx)) }()
				roomReports, rooms = im.RelayRooms(ctx, rooms, rl)
			}
			if len(rooms) > 0 {
				roomReports = append(roomReports, im.ReplayRooms(ctx, rooms)...)
			}
			var reports []*migrate.Report
			for _, job := range jobs {
				rep, err := im.FinishUser(ctx, job, nil)
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if err != nil {
					slog.Error("user failed", "user", job.User.UserID, "err", err)
					failed++
					continue
				}
				reports = append(reports, rep)
			}
			printRoomSummary(cmd.OutOrStdout(), roomReports)
			finishImport(ctx, cmd.OutOrStdout(), im, a, users, reports)
			if failed > 0 {
				return fmt.Errorf("%d of %d users failed", failed, len(users))
			}
			return nil
		},
	}
	dst.register(cmd)
	fs := cmd.Flags()
	fs.StringVar(&relayOpts.name, "relay-name", "", "server name of the temporary relay that hands rooms only your server was in to Continuwuity with their original events (needs export --synapse-db --synapse-signing-key)")
	fs.StringVar(&relayOpts.listen, "relay-listen", ":8448", "address the relay listens on")
	fs.StringVar(&relayOpts.cert, "relay-tls-cert", "", "TLS certificate of the relay; self-signed when unset")
	fs.StringVar(&relayOpts.key, "relay-tls-key", "", "TLS key of the relay")
	fs.StringVar(&dir, "archive", "exodus-archive", "archive directory")
	return cmd
}

func newMigrateCmd() *cobra.Command {
	var src sourceFlags
	var dst destFlags
	var dir string
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Export and import in one pass while the source is online",
		Long: `Export each user and import it into Continuwuity immediately. With a new
server name, the old account invites the new one into every room and hands
over its power level, so invite-only and local-only rooms are kept.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			s, err := src.open(ctx)
			if err != nil {
				return err
			}
			defer s.Close()
			a, err := archive.Create(dir, s.serverName)
			if err != nil {
				return err
			}
			im, err := dst.importer(ctx, a, s.userIDs())
			if err != nil {
				return err
			}
			if im.Admin != nil && slices.ContainsFunc(s.users, func(u migrate.SynapseUser) bool { return u.Guest }) {
				unregister, err := registerAppservice(ctx, im)
				if err != nil {
					return err
				}
				defer unregister()
			}
			defer im.Close(context.WithoutCancel(ctx))
			exp := s.exporter(a)
			var users []*archive.User
			var reports []*migrate.Report
			err = s.each(ctx, func(sess *migrate.Session) error {
				u, err := exp.ExportUser(ctx, sess)
				if err != nil {
					return fmt.Errorf("export: %w", err)
				}
				users = append(users, u)
				rep, err := im.ImportUser(ctx, u, sess)
				if err != nil {
					return fmt.Errorf("import: %w", err)
				}
				reports = append(reports, rep)
				return nil
			})
			if ctx.Err() != nil {
				return ctx.Err()
			}
			for _, d := range s.deactivated {
				u, derr := exp.ExportDeactivated(d.UserID)
				if derr == nil {
					users = append(users, u)
					var rep *migrate.Report
					if rep, derr = im.ImportUser(ctx, u, nil); derr == nil {
						reports = append(reports, rep)
					}
				}
				err = errors.Join(err, derr)
			}
			err = errors.Join(err, exp.ExportServer(ctx))
			finishImport(ctx, cmd.OutOrStdout(), im, a, users, reports)
			return err
		},
	}
	src.register(cmd)
	dst.register(cmd)
	cmd.Flags().StringVar(&dir, "archive", "exodus-archive", "archive directory used as working state")
	return cmd
}

func newLinkSSOCmd() *cobra.Command {
	var dir, to, adminToken string
	cmd := &cobra.Command{
		Use:   "link-sso",
		Short: "Link migrated users to their SSO identities once OIDC is enabled",
		Long: `Configuring OIDC on Continuwuity turns off password logins, which the import
needs, and linking identities needs OIDC. Run the import first, then enable
OIDC, then run this command.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			c, err := mx.New(to, adminToken)
			if err != nil {
				return err
			}
			admin, err := migrate.NewContinuwuityAdmin(ctx, c)
			if err != nil {
				return err
			}
			linked, failures := migrate.LinkSSO(ctx, a, admin)
			out := cmd.OutOrStdout()
			for _, f := range failures {
				fmt.Fprintf(out, "%s %s: %s\n", f.Step, f.Target, f.Error)
			}
			fmt.Fprintf(out, "%d users linked to their SSO identity\n", linked)
			if len(failures) > 0 {
				return fmt.Errorf("%d links failed", len(failures))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "archive", "exodus-archive", "archive directory")
	cmd.Flags().StringVar(&to, "to", "", "Continuwuity client API URL")
	cmd.Flags().StringVar(&adminToken, "to-admin-token", os.Getenv("EXODUS_TO_ADMIN_TOKEN"), "access token of a Continuwuity server admin [$EXODUS_TO_ADMIN_TOKEN]")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

func newProxyCmd() *cobra.Command {
	var dir, listen, upstream, pepper, macaroonSecret, signingKey, masConfig string
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Serve Continuwuity with old sessions, passwords and media links kept working",
		Long: `Run in front of Continuwuity, for both client and federation traffic. The
proxy swaps old Synapse access tokens for the migrated sessions, sets each
user's Synapse password on their first login (needs export --synapse-db), and
serves media under its old IDs.

Without --upstream it only serves archived media, for a retired server name.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := archive.Open(dir)
			if err != nil {
				return err
			}
			var up *url.URL
			if upstream != "" {
				if up, err = url.Parse(upstream); err != nil {
					return err
				}
			}
			key, err := proxy.SynapseMacaroonKey(macaroonSecret, signingKey)
			if err != nil {
				return err
			}
			var schemes map[int]proxy.MASScheme
			if masConfig != "" {
				if schemes, err = proxy.LoadMASSchemes(masConfig); err != nil {
					return err
				}
			}
			p, err := proxy.New(a, up, pepper, key, schemes)
			if err != nil {
				return err
			}
			srv := &http.Server{Addr: listen, Handler: p, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				<-cmd.Context().Done()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = srv.Shutdown(ctx)
			}()
			slog.Info("listening", "addr", listen, "upstream", upstream)
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			<-stopped
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "archive", "exodus-archive", "archive directory")
	cmd.Flags().StringVar(&listen, "listen", ":8008", "address to listen on")
	cmd.Flags().StringVar(&upstream, "upstream", "", "Continuwuity URL to forward to")
	cmd.Flags().StringVar(&pepper, "synapse-password-pepper", os.Getenv("EXODUS_SYNAPSE_PASSWORD_PEPPER"), "Synapse password_config.pepper, if set [$EXODUS_SYNAPSE_PASSWORD_PEPPER]")
	cmd.Flags().StringVar(&macaroonSecret, "synapse-macaroon-secret", os.Getenv("EXODUS_SYNAPSE_MACAROON_SECRET"), "Synapse macaroon_secret_key (or registration_shared_secret if unset), to keep guests logged in [$EXODUS_SYNAPSE_MACAROON_SECRET]")
	cmd.Flags().StringVar(&masConfig, "mas-config", "", "MAS configuration file, for password schemes with a secret or Unicode normalization")
	cmd.Flags().StringVar(&signingKey, "synapse-signing-key", "", "Synapse signing key file, when neither macaroon_secret_key nor registration_shared_secret is set")
	return cmd
}

func registerAppservice(ctx context.Context, im *migrate.Importer) (unregister func(), err error) {
	if im.Appservice, err = migrate.RegisterAppservice(ctx, im.Admin, im.Dest); err != nil {
		return nil, err
	}
	return func() {
		if err := im.Appservice.Unregister(context.WithoutCancel(ctx), im.Admin); err != nil {
			slog.Error("could not unregister the exodus appservice", "err", err)
		}
	}, nil
}

// Reports are filed before accounts are locked or suspended.
func finishImport(ctx context.Context, out io.Writer, im *migrate.Importer, a *archive.Archive, users []*archive.User, reports []*migrate.Report) {
	reports = retryJoins(ctx, im, users, reports)
	notes, serverFailures := im.ImportServer(ctx)
	failures := slices.Concat(im.RestoreInvites(ctx, users), im.RestoreKnocks(ctx, users), im.ApplyStatus(ctx, users), serverFailures)
	printSummary(out, a, users, reports, failures, notes)
}

// retryJoins retries failed joins: later-migrated accounts can now invite locally.
func retryJoins(ctx context.Context, im *migrate.Importer, users []*archive.User, reports []*migrate.Report) []*migrate.Report {
	if len(users) < 2 {
		return reports
	}
	byID := map[string]*archive.User{}
	for _, u := range users {
		byID[u.UserID] = u
	}
	for i, r := range reports {
		if !slices.ContainsFunc(r.Failures, func(f migrate.Failure) bool { return f.Step == "join" }) {
			continue
		}
		slog.Info("retrying failed joins", "user", r.SourceUserID)
		rep, err := im.ImportUser(ctx, byID[r.SourceUserID], nil)
		if err != nil {
			slog.Error("retry failed", "user", r.SourceUserID, "err", err)
			continue
		}
		reports[i] = rep
	}
	return reports
}

// The relay only answers the destination server, whose key comes from --to.
func startRelay(ctx context.Context, a *archive.Archive, destURL string, f relayFlags, im *migrate.Importer) (*relay.Relay, error) {
	raw, err := a.SigningKey()
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, errors.New("--relay-name requires exporting with --synapse-signing-key")
	}
	if im.Admin == nil {
		return nil, errors.New("--relay-name requires --to-admin-token")
	}
	key, err := federation.ParseSynapseKey(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	keys, err := a.ServerKeys()
	if err != nil {
		return nil, err
	}
	rl := relay.New(f.name, a.Manifest.ServerName, key, keys)
	if err := rl.Trust(ctx, im.Admin.ServerName(), strings.TrimRight(destURL, "/")+"/_matrix/key/v2/server"); err != nil {
		return nil, err
	}
	return rl, rl.Start(f.listen, f.cert, f.key)
}

func exportRooms(ctx context.Context, exp *migrate.Exporter, users []*archive.User, member *mautrix.Client) error {
	ids := migrate.LocalOnlyRooms(users)
	if len(ids) == 0 {
		return nil
	}
	known := map[string]bool{}
	for _, u := range users {
		for _, m := range u.Media {
			known[m.MXC] = true
		}
	}
	var errs []error
	for _, id := range ids {
		if err := exp.ExportRoom(ctx, id, known, member); err != nil {
			slog.Error("room export failed", "room", id, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// needsAppservice reports whether the import must act as other users.
func needsAppservice(users []*archive.User, rooms []*archive.ArchivedRoom, srv *archive.Server) bool {
	if len(rooms) > 0 || (srv != nil && len(srv.Reports)+len(srv.ToDevice) > 0) {
		return true
	}
	return slices.ContainsFunc(users, func(u *archive.User) bool { return u.CrossSigning != nil || len(u.Devices) > 0 || u.Guest })
}

func printRoomSummary(out io.Writer, reports []*migrate.RoomReport) {
	for _, r := range reports {
		fmt.Fprintf(out, "room %s -> %s: %d events replayed, %d skipped, %d encrypted skipped, %d failures\n",
			r.RoomID, r.NewRoomID, r.Replayed, r.Skipped, r.Encrypted, len(r.Failures))
		for _, f := range r.Failures {
			fmt.Fprintf(out, "  - %s %s: %s\n", f.Step, f.Target, f.Error)
		}
		for _, w := range r.Warnings {
			fmt.Fprintf(out, "  ! %s\n", w)
		}
	}
}

func printSummary(out io.Writer, a *archive.Archive, users []*archive.User, reports []*migrate.Report, status []migrate.Failure, notes []string) {
	rooms := map[string]int{}
	admins := map[string]bool{}
	for _, u := range users {
		rooms[u.UserID] = len(u.Rooms)
		admins[u.UserID] = u.Admin
	}
	fmt.Fprintln(out)
	for _, r := range reports {
		fmt.Fprintf(out, "%s -> %s: %d/%d rooms joined, %d failures\n",
			r.SourceUserID, r.DestUserID, r.RoomsJoined, rooms[r.SourceUserID], len(r.Failures))
		for _, f := range r.Failures {
			fmt.Fprintf(out, "  - %s %s: %s\n", f.Step, f.Target, f.Error)
		}
	}
	for _, f := range status {
		fmt.Fprintf(out, "%s %s: %s\n", f.Step, f.Target, f.Error)
	}
	for _, n := range notes {
		fmt.Fprintln(out, n)
	}
	var hinted bool
	for _, r := range reports {
		if !admins[r.SourceUserID] || r.AdminGranted {
			continue
		}
		if !hinted {
			fmt.Fprintln(out, "\nRestore server admin rights by sending these in the Continuwuity admin room:")
			hinted = true
		}
		fmt.Fprintln(out, "  "+migrate.AdminHint(r.DestUserID))
	}
	if slices.ContainsFunc(users, func(u *archive.User) bool { return u.ShadowBanned }) {
		fmt.Fprintln(out, "\nContinuwuity has no shadow bans: run exodus proxy, which enforces them")
	}
	if slices.ContainsFunc(users, func(u *archive.User) bool { return len(u.ExternalIDs) > 0 }) {
		fmt.Fprintln(out, "\nSome users log in with SSO: once OIDC is enabled on Continuwuity, run exodus link-sso")
	}
	creds := a.CredentialsPath()
	if _, err := os.Stat(creds); err == nil {
		fmt.Fprintf(out, "\nGenerated passwords are in %s\n", creds)
	}
	fmt.Fprintf(out, "Per-user details: %s/users/*/import-report.json\n", a.Dir)
}
