package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// Apps, membership, teams and resource sharing.
//
// Revocation: membership, team and grant changes take effect for the next transaction. Nothing
// authorization-related is cached across transactions; each request re-reads the caller's role,
// teams and grants. Work already authorized (a blob stream that has started, a transaction in
// flight) completes under the decision it was made with. Receipt replays, history reads, exports
// and each upload part are re-authorized when they happen.

type Sharing struct {
	*Core
	authz    Authorizer
	records  *Records
	blobs    *Blobs
	AppEnv   string
	Registry *auth.Registry
}

// AppInfo describes the caller's standing in an app.
type AppInfo struct {
	App   string            `json:"app"`
	Role  string            `json:"role"`
	Teams map[string]string `json:"teams"`
}

func (s *Sharing) App(ctx context.Context, c Ctx) (*AppInfo, error) {
	var out *AppInfo
	err := s.inApp(ctx, c, func(_ pgx.Tx, a *Access) error {
		out = &AppInfo{App: a.App, Role: a.Role, Teams: a.Teams}
		return nil
	})
	return out, err
}

type Member struct {
	Subject   string    `json:"subject"`
	Role      string    `json:"role"`
	AddedBy   string    `json:"added_by"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Sharing) Members(ctx context.Context, c Ctx) ([]Member, error) {
	var out []Member
	err := s.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		rows, err := tx.Query(ctx, `SELECT subject, role, added_by, created_at FROM app_members WHERE app = $1 ORDER BY subject`, c.App)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Member])
		return err
	})
	return out, err
}

func (s *Sharing) requireAppAdmin(ctx context.Context, tx pgx.Tx, c Ctx, a *Access, target string) error {
	if a.Role != "admin" {
		return s.deny(c, auth.AppManage, "app_member", target, nil, "app role "+a.Role, errs.Forbidden("managing members requires the app admin role"))
	}
	_, err := s.check(ctx, tx, c, auth.AppManage, "app_member", target, nil, checkOpts{noConceal: true, skipAllow: true})
	return err
}

// PutMember adds a member or changes a role. The subject must be a registered principal.
func (s *Sharing) PutMember(ctx context.Context, c Ctx, subject, role string) error {
	if _, ok := roleRank[role]; !ok {
		return errs.Invalid("role must be viewer, member, editor or admin")
	}
	return s.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if err := s.requireAppAdmin(ctx, tx, c, a, subject); err != nil {
			return err
		}
		replay, err := s.operations.claim(ctx, tx, c, Operation{Type: "member.set", Target: subject, Payload: role}, 0, "")
		if err != nil {
			return err
		}
		if replay != nil {
			return nil
		}
		if p, err := s.Registry.GetWith(ctx, tx, subject); err != nil || p == nil {
			if err == nil {
				err = errs.Invalid("unknown principal %s", subject)
			}
			return err
		}
		if err := s.keepAnAdmin(ctx, tx, c.App, subject, role); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO app_members (app, subject, role, added_by) VALUES ($1,$2,$3,$4)
			ON CONFLICT (app, subject) DO UPDATE SET role = EXCLUDED.role`, c.App, subject, role, c.Principal.Subject); err != nil {
			return err
		}
		if err := s.note(ctx, tx, c, auth.AppManage, "app_member", subject, "allow", "member role set to "+role, nil, nil); err != nil {
			return err
		}
		return s.operations.complete(ctx, tx, c, "app_member", subject, 0, nil)
	})
}

func (s *Sharing) RemoveMember(ctx context.Context, c Ctx, subject string) error {
	return s.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if err := s.requireAppAdmin(ctx, tx, c, a, subject); err != nil {
			return err
		}
		replay, err := s.operations.claim(ctx, tx, c, Operation{Type: "member.remove", Target: subject}, 0, "")
		if err != nil {
			return err
		}
		if replay != nil {
			return nil
		}
		if err := s.keepAnAdmin(ctx, tx, c.App, subject, ""); err != nil {
			return err
		}
		if err := s.operations.complete(ctx, tx, c, "app_member", subject, 0, nil); err != nil {
			return err
		}
		if err := s.note(ctx, tx, c, auth.AppManage, "app_member", subject, "allow", "member removed", nil, nil); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM app_members WHERE app = $1 AND subject = $2`, c.App, subject)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errs.NotFound("not a member")
		}
		if _, err := tx.Exec(ctx, `DELETE FROM team_members WHERE app = $1 AND subject = $2`, c.App, subject); err != nil {
			return err
		}
		return nil
	})
}

// keepAnAdmin refuses changes that would leave the app without an admin.
func (s *Sharing) keepAnAdmin(ctx context.Context, tx pgx.Tx, app, subject, newRole string) error {
	if newRole == "admin" {
		return nil
	}
	var others int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM app_members WHERE app = $1 AND role = 'admin' AND subject <> $2`,
		app, subject).Scan(&others); err != nil {
		return err
	}
	var isAdmin bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_members WHERE app = $1 AND subject = $2 AND role = 'admin')`,
		app, subject).Scan(&isAdmin); err != nil {
		return err
	}
	if isAdmin && others == 0 {
		return errs.Conflict("an app must keep at least one admin")
	}
	return nil
}

type Team struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	CreatedBy string            `json:"created_by"`
	CreatedAt time.Time         `json:"created_at"`
	Members   map[string]string `json:"members"`
}

func (s *Sharing) CreateTeam(ctx context.Context, c Ctx, name string) (*Team, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 120 {
		return nil, errs.Invalid("team name must be 1-120 characters")
	}
	var out *Team
	err := s.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if !a.AtLeast("member") {
			return s.deny(c, auth.TeamManage, "team", "", nil, "app role viewer", errs.Forbidden("viewers cannot create teams"))
		}
		replay, err := s.operations.claim(ctx, tx, c, Operation{Type: "team.create", Target: "teams", Payload: name}, 0, "")
		if err != nil {
			return err
		}
		if replay != nil {
			out = &Team{}
			return decodeOutcome(replay, out)
		}
		id := store.NewID("tm")
		tag, err := tx.Exec(ctx, `INSERT INTO teams (app, id, name, created_by) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
			c.App, id, name, c.Principal.Subject)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errs.Conflict("a team named %q exists", name)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO team_members (app, team_id, subject, role, added_by) VALUES ($1,$2,$3,'admin',$3)`,
			c.App, id, c.Principal.Subject); err != nil {
			return err
		}
		out = &Team{ID: id, Name: name, CreatedBy: c.Principal.Subject, CreatedAt: time.Now().UTC(),
			Members: map[string]string{c.Principal.Subject: "admin"}}
		if err := s.note(ctx, tx, c, auth.TeamManage, "team", id, "allow", "team created", nil, nil); err != nil {
			return err
		}
		return s.operations.complete(ctx, tx, c, "team", id, 0, outcome(out))
	})
	return out, err
}

func (s *Sharing) Teams(ctx context.Context, c Ctx) ([]Team, error) {
	var out []Team
	err := s.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		rows, err := tx.Query(ctx, `SELECT t.id, t.name, t.created_by, t.created_at,
			coalesce((SELECT jsonb_object_agg(m.subject, m.role) FROM team_members m WHERE m.app = t.app AND m.team_id = t.id), '{}')
			FROM teams t WHERE t.app = $1 ORDER BY t.name`, c.App)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Team])
		return err
	})
	return out, err
}

func (s *Sharing) teamAdmin(c Ctx, a *Access, team string, created string) error {
	if a.Role == "admin" || a.Teams[team] == "admin" || created == c.Principal.Subject {
		return nil
	}
	return s.deny(c, auth.TeamManage, "team", team, nil, "not a team admin", errs.Forbidden("managing a team requires being its admin"))
}

func (s *Sharing) PutTeamMember(ctx context.Context, c Ctx, team, subject, role string) error {
	if role != "viewer" && role != "editor" && role != "admin" {
		return errs.Invalid("team role must be viewer, editor or admin")
	}
	return s.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		var created string
		if err := tx.QueryRow(ctx, `SELECT created_by FROM teams WHERE app = $1 AND id = $2`, c.App, team).Scan(&created); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errs.NotFound("team not found")
			}
			return err
		}
		if err := s.teamAdmin(c, a, team, created); err != nil {
			return err
		}
		var member bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_members WHERE app = $1 AND subject = $2)`, c.App, subject).Scan(&member); err != nil {
			return err
		}
		if !member {
			return errs.Invalid("%s is not a member of this app", subject)
		}
		replay, err := s.operations.claim(ctx, tx, c, Operation{Type: "team.member.set", Target: team + "/" + subject, Payload: role}, 0, "")
		if err != nil {
			return err
		}
		if replay != nil {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO team_members (app, team_id, subject, role, added_by) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (app, team_id, subject) DO UPDATE SET role = EXCLUDED.role`, c.App, team, subject, role, c.Principal.Subject); err != nil {
			return err
		}
		if err := s.note(ctx, tx, c, auth.TeamManage, "team", team, "allow", "team member "+subject+" set to "+role, nil, nil); err != nil {
			return err
		}
		return s.operations.complete(ctx, tx, c, "team", team, 0, nil)
	})
}

func (s *Sharing) RemoveTeamMember(ctx context.Context, c Ctx, team, subject string) error {
	return s.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		var created string
		if err := tx.QueryRow(ctx, `SELECT created_by FROM teams WHERE app = $1 AND id = $2`, c.App, team).Scan(&created); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errs.NotFound("team not found")
			}
			return err
		}
		if subject != c.Principal.Subject { // anyone may leave a team
			if err := s.teamAdmin(c, a, team, created); err != nil {
				return err
			}
		}
		replay, err := s.operations.claim(ctx, tx, c, Operation{Type: "team.member.remove", Target: team + "/" + subject}, 0, "")
		if err != nil {
			return err
		}
		if replay != nil {
			return nil
		}
		tag, err := tx.Exec(ctx, `DELETE FROM team_members WHERE app = $1 AND team_id = $2 AND subject = $3`, c.App, team, subject)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errs.NotFound("not a team member")
		}
		if err := s.note(ctx, tx, c, auth.TeamManage, "team", team, "allow", "team member "+subject+" removed", nil, nil); err != nil {
			return err
		}
		return s.operations.complete(ctx, tx, c, "team", team, 0, nil)
	})
}

// ---- resource sharing ----------------------------------------------------------------------------

// ResourceRef names a record (Collection set) or a blob.
type ResourceRef struct {
	Kind       string // record | blob
	Collection string
	ID         string
}

type Grant struct {
	ID        string    `json:"id"`
	Subject   *string   `json:"subject"`
	TeamID    *string   `json:"team_id"`
	Role      string    `json:"role"`
	CanShare  bool      `json:"can_share"`
	GrantedBy string    `json:"granted_by"`
	CreatedAt time.Time `json:"created_at"`
}

type GrantInput struct {
	Subject  string
	TeamID   string
	Role     string // viewer | editor
	CanShare bool
}

// load reads a live resource visible to the caller and its sharing rights.
func (s *Sharing) load(ctx context.Context, tx pgx.Tx, c Ctx, a *Access, ref ResourceRef) (Resource, markings.Marking, Perm, []string, error) {
	var res Resource
	var banner string
	var team *string
	var q string
	var args []any
	switch ref.Kind {
	case "record":
		q, args = `SELECT id, owner, visibility, team_id, marking FROM records WHERE app = $1 AND collection = $2 AND id = $3 AND deleted_at IS NULL`,
			[]any{c.App, ref.Collection, ref.ID}
	case "blob":
		q, args = `SELECT id, owner, visibility, team_id, marking FROM blobs WHERE app = $1 AND id = $2 AND state = 'active'`,
			[]any{c.App, ref.ID}
	default:
		return res, markings.Marking{}, 0, nil, errs.Invalid("resource kind must be record or blob")
	}
	err := tx.QueryRow(ctx, q, args...).Scan(&res.ID, &res.Owner, &res.Visibility, &team, &banner)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, markings.Marking{}, 0, nil, errs.NotFound("%s not found", ref.Kind)
	}
	if err != nil {
		return res, markings.Marking{}, 0, nil, err
	}
	res.Kind = ref.Kind
	if team != nil {
		res.TeamID = *team
	}
	m, err := markings.Parse(banner)
	if err != nil {
		return res, m, 0, nil, errs.Integrity("stored marking is invalid")
	}
	readAction := auth.RecordRead
	if ref.Kind == "blob" {
		readAction = auth.BlobReadMeta
	}
	if _, err := s.check(ctx, tx, c, readAction, ref.Kind, ref.ID, &m, checkOpts{skipAllow: true}); err != nil {
		return res, m, 0, nil, err
	}
	perm, why, err := s.authz.Permissions(ctx, tx, a, res)
	return res, m, perm, why, err
}

func shareAction(kind string) auth.Action {
	if kind == "blob" {
		return auth.BlobShare
	}
	return auth.RecordShare
}

func (s *Sharing) requireShare(ctx context.Context, tx pgx.Tx, c Ctx, a *Access, ref ResourceRef, need Perm) (Resource, error) {
	res, m, perm, why, err := s.load(ctx, tx, c, a, ref)
	if err != nil {
		return res, err
	}
	if !perm.Has(need) {
		return res, s.deny(c, shareAction(ref.Kind), ref.Kind, ref.ID, &m, "sharing: "+strings.Join(why, ","),
			errs.Forbidden("you may not change who can access this %s", ref.Kind))
	}
	// Sharing never overrides classification: the share action still needs the CUI policy to pass.
	_, err = s.check(ctx, tx, c, shareAction(ref.Kind), ref.Kind, ref.ID, &m, checkOpts{noConceal: true})
	return res, err
}

// SetVisibility changes private/team/app visibility. Requires share permission.
func (s *Sharing) SetVisibility(ctx context.Context, c Ctx, ref ResourceRef, visibility, team string) error {
	return s.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if _, err := s.requireShare(ctx, tx, c, a, ref, PermShare); err != nil {
			return err
		}
		replay, err := s.operations.claim(ctx, tx, c, Operation{Type: "sharing.visibility", Target: ref.Kind + "/" + ref.Collection + "/" + ref.ID, Payload: []string{visibility, team}}, 0, "")
		if err != nil {
			return err
		}
		if replay != nil {
			return nil
		}
		var teamID *string
		switch visibility {
		case "private", "app":
			if team != "" {
				return errs.Invalid("team_id applies only to team visibility")
			}
		case "team":
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM teams WHERE app = $1 AND id = $2)`, c.App, team).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return errs.Invalid("team not found")
			}
			teamID = &team
		default:
			return errs.Invalid("visibility must be private, team or app")
		}
		var changed bool
		if err := tx.QueryRow(ctx, `SELECT sb_set_visibility($1,$2,$3,$4)`, ref.Kind, ref.ID, visibility, teamID).Scan(&changed); err != nil {
			return err
		}
		if !changed {
			return errs.NotFound("resource not found")
		}

		if err := s.note(ctx, tx, c, shareAction(ref.Kind), ref.Kind, ref.ID, "allow", "visibility set to "+visibility, nil, nil); err != nil {
			return err
		}
		return s.operations.complete(ctx, tx, c, ref.Kind, ref.ID, 0, nil)
	})
}

// AddGrant gives a subject or team viewer/editor access. can_share requires manage permission.
func (s *Sharing) AddGrant(ctx context.Context, c Ctx, ref ResourceRef, in GrantInput) (*Grant, error) {
	if in.Role != "viewer" && in.Role != "editor" {
		return nil, errs.Invalid("role must be viewer or editor")
	}
	if (in.Subject == "") == (in.TeamID == "") {
		return nil, errs.Invalid("grant to exactly one of subject or team_id")
	}
	var out *Grant
	err := s.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		need := PermShare
		if in.CanShare {
			need |= PermManage
		}
		res, err := s.requireShare(ctx, tx, c, a, ref, need)
		if err != nil {
			return err
		}
		opType := "sharing.grant"
		if in.CanShare {
			opType = "sharing.delegate"
		}
		replay, err := s.operations.claim(ctx, tx, c, Operation{Type: opType, Target: ref.Kind + "/" + ref.Collection + "/" + ref.ID, Payload: in}, 0, "")
		if err != nil {
			return err
		}
		if replay != nil {
			out = &Grant{}
			return decodeOutcome(replay, out)
		}
		if in.Subject != "" {
			var member bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_members WHERE app = $1 AND subject = $2)`, c.App, in.Subject).Scan(&member); err != nil {
				return err
			}
			if !member {
				return errs.Invalid("%s is not a member of this app", in.Subject)
			}
		}
		g := &Grant{ID: store.NewID("gr"), Subject: optional(in.Subject), TeamID: optional(in.TeamID), Role: in.Role,
			CanShare: in.CanShare, GrantedBy: c.Principal.Subject}
		var recordID, blobID *string
		if ref.Kind == "record" {
			recordID = &ref.ID
		} else {
			blobID = &ref.ID
		}
		err = tx.QueryRow(ctx, `INSERT INTO resource_grants (id, app, record_id, blob_id, subject, team_id, role, can_share,
			resource_owner, granted_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (app, (coalesce(record_id, blob_id)), (coalesce(subject, '')), (coalesce(team_id, '')))
			DO UPDATE SET role = EXCLUDED.role, can_share = EXCLUDED.can_share
			RETURNING id, created_at, granted_by`, g.ID, c.App, recordID, blobID, g.Subject, g.TeamID, g.Role, g.CanShare, res.Owner,
			c.Principal.Subject).Scan(&g.ID, &g.CreatedAt, &g.GrantedBy)
		if err != nil {
			return err
		}
		out = g
		if err := s.note(ctx, tx, c, shareAction(ref.Kind), ref.Kind, ref.ID, "allow", "granted "+in.Role, nil, map[string]any{"grant": g.ID, "subject": in.Subject, "team_id": in.TeamID, "can_share": in.CanShare}); err != nil {
			return err
		}
		return s.operations.complete(ctx, tx, c, ref.Kind, ref.ID, 0, outcome(g))
	})
	return out, err
}

func (s *Sharing) Grants(ctx context.Context, c Ctx, ref ResourceRef) ([]Grant, error) {
	var out []Grant
	err := s.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if _, err := s.requireShare(ctx, tx, c, a, ref, PermShare); err != nil {
			return err
		}
		col := "record_id"
		if ref.Kind == "blob" {
			col = "blob_id"
		}
		rows, err := tx.Query(ctx, `SELECT id, subject, team_id, role, can_share, granted_by, created_at FROM resource_grants
			WHERE app = $1 AND `+col+` = $2 ORDER BY created_at`, c.App, ref.ID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Grant])
		return err
	})
	return out, err
}

func (s *Sharing) RemoveGrant(ctx context.Context, c Ctx, ref ResourceRef, grantID string) error {
	return s.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if _, err := s.requireShare(ctx, tx, c, a, ref, PermShare); err != nil {
			return err
		}
		replay, err := s.operations.claim(ctx, tx, c, Operation{Type: "sharing.revoke", Target: ref.Kind + "/" + ref.Collection + "/" + ref.ID, Payload: grantID}, 0, "")
		if err != nil {
			return err
		}
		if replay != nil {
			return nil
		}
		col := "record_id"
		if ref.Kind == "blob" {
			col = "blob_id"
		}
		tag, err := tx.Exec(ctx, `DELETE FROM resource_grants WHERE app = $1 AND id = $2 AND `+col+` = $3`, c.App, grantID, ref.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errs.NotFound("grant not found")
		}
		if err := s.note(ctx, tx, c, shareAction(ref.Kind), ref.Kind, ref.ID, "allow", "grant revoked", nil, map[string]any{"grant": grantID}); err != nil {
			return err
		}
		return s.operations.complete(ctx, tx, c, ref.Kind, ref.ID, 0, nil)
	})
}

// ---- explanation ---------------------------------------------------------------------------------

// Explanation says why a subject can or cannot do something with a resource. Reason codes name
// rules; they never reveal resources the asking admin cannot see.
type Explanation struct {
	Subject     string          `json:"subject"`
	AppRole     *string         `json:"app_role"`
	Permissions []string        `json:"permissions"`
	Sharing     []string        `json:"sharing_reasons"`
	Policy      map[string]Rule `json:"policy"`
	Allowed     map[string]bool `json:"allowed"`
}

type Rule struct {
	Allowed bool   `json:"allowed"`
	Code    string `json:"code"`
}

// Explain is for app admins (apps:manage scope plus the admin role).
func (s *Sharing) Explain(ctx context.Context, c Ctx, subject string, ref ResourceRef) (*Explanation, error) {
	var out *Explanation
	err := s.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if err := s.requireAppAdmin(ctx, tx, c, a, subject); err != nil {
			return err
		}
		res, m, _, _, err := s.load(ctx, tx, c, a, ref)
		if err != nil {
			if errs.Is(err, "not_found") || errs.Is(err, "forbidden") {
				return errs.NotFound("resource_not_visible_to_caller")
			}
			return err
		}
		p, err := s.Registry.GetWith(ctx, tx, subject)
		if err != nil {
			return err
		}
		out = &Explanation{Subject: subject, Permissions: []string{}, Sharing: []string{}, Policy: map[string]Rule{}, Allowed: map[string]bool{}}
		target, err := loadAccess(ctx, tx, c.App, subject)
		if err != nil {
			return err
		}
		var role *string
		if err := tx.QueryRow(ctx, `SELECT role FROM app_members WHERE app = $1 AND subject = $2`, c.App, subject).Scan(&role); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		out.AppRole = role
		if p == nil || role == nil {
			out.Sharing = append(out.Sharing, "not_app_member")
			return s.note(ctx, tx, c, auth.AppManage, ref.Kind, ref.ID, "allow", "explained access for "+subject, nil, nil)
		}
		if target == nil { // loadAccess only answers for the scope's own subject; rebuild for the target
			target = &Access{App: c.App, Subject: subject, Role: *role, Teams: map[string]string{}}
			rows, err := tx.Query(ctx, `SELECT team_id, role FROM team_members WHERE app = $1 AND subject = $2`, c.App, subject)
			if err != nil {
				return err
			}
			for rows.Next() {
				var t, r string
				if err := rows.Scan(&t, &r); err != nil {
					rows.Close()
					return err
				}
				target.Teams[t] = r
			}
			rows.Close()
		}
		perm, why, err := s.authz.Permissions(ctx, tx, target, res)
		if err != nil {
			return err
		}
		out.Permissions, out.Sharing = perm.Names(), why
		actions := map[string]auth.Action{"read": auth.RecordRead, "read_content": auth.RecordReadContent, "write": auth.RecordUpdate,
			"delete": auth.RecordDelete, "share": auth.RecordShare}
		if ref.Kind == "blob" {
			actions = map[string]auth.Action{"read": auth.BlobReadMeta, "read_content": auth.BlobReadContent, "delete": auth.BlobDelete, "share": auth.BlobShare}
		}
		needs := map[string]Perm{"read": PermRead, "read_content": PermRead, "write": PermWrite, "delete": PermManage, "share": PermShare}
		for name, action := range actions {
			d := s.Policy.Evaluate(p, action, &m)
			out.Policy[name] = Rule{Allowed: d.Allowed, Code: d.Code}
			out.Allowed[name] = d.Allowed && perm.Has(needs[name])
		}
		return s.note(ctx, tx, c, auth.AppManage, ref.Kind, ref.ID, "allow", "explained access for "+subject, nil, nil)
	})
	return out, err
}
