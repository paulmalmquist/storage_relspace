package service_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func notes(t *testing.T, env *testenv.Env) {
	t.Helper()
	if _, err := env.C.Records.CreateCollection(context.Background(), env.Ctx(t, "admin@rel.test"),
		service.CollectionInput{Name: "notes", Marking: markings.None(), IndexedFields: []string{"tag"}}); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultPrivateAndAppBoundary(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	eng, mate := env.Ctx(t, "engineer@rel.test"), env.Ctx(t, "teammate@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "notes", in(`{"tag":"mine"}`)))
	_, err := env.C.Records.Get(ctx, mate, "notes", r.ID)
	wantCode(t, err, "not_found")
	items, _, _ := env.C.Records.Query(ctx, mate, "notes", nil, 0, "")
	if len(items) != 0 {
		t.Fatal("private record listed to another member")
	}
	// The app named in the request selects a scope; it grants nothing. outsider is an admin of the
	// other app and not a member of this one.
	_, err = env.C.Records.Get(ctx, env.CtxIn(t, testenv.App, "outsider@rel.test"), "notes", r.ID)
	wantCode(t, err, "not_found")
	// The same record id under the other app does not exist.
	_, err = env.C.Records.Get(ctx, env.CtxIn(t, testenv.Other, "admin@rel.test"), "notes", r.ID)
	wantCode(t, err, "not_found")
	// Unknown and malformed apps look the same as apps the caller does not belong to.
	for _, app := range []string{"nosuch:test", "BAD", ""} {
		_, err = env.C.Records.Get(ctx, env.CtxIn(t, app, "engineer@rel.test"), "notes", r.ID)
		wantCode(t, err, "not_found")
	}
}

func TestTeamAndAppSharing(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	eng, mate, intern := env.Ctx(t, "engineer@rel.test"), env.Ctx(t, "teammate@rel.test"), env.Ctx(t, "intern@rel.test")
	team := must[*service.Team](t)(env.C.Sharing.CreateTeam(ctx, eng, "propulsion"))
	if err := env.C.Sharing.PutTeamMember(ctx, eng, team.ID, "teammate@rel.test", "editor"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, env.C.Sharing.PutTeamMember(ctx, eng, team.ID, "outsider@rel.test", "viewer"), "validation_failed")
	wantCode(t, env.C.Sharing.PutTeamMember(ctx, mate, team.ID, "intern@rel.test", "viewer"), "forbidden")

	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "notes", service.RecordInput{Data: doc(`{"tag":"t"}`), Visibility: "team", TeamID: team.ID}))
	got := must[*service.Record](t)(env.C.Records.Get(ctx, mate, "notes", r.ID))
	if got.Data["tag"] != "t" {
		t.Fatal("team member cannot read")
	}
	upd := must[*service.Record](t)(env.C.Records.Update(ctx, mate, "notes", r.ID, in(`{"tag":"edited"}`), 1))
	// Editing is not sharing or deleting.
	wantCode(t, env.C.Sharing.SetVisibility(ctx, mate, service.ResourceRef{Kind: "record", Collection: "notes", ID: r.ID}, "app", ""), "forbidden")
	v := upd.Version
	wantCode(t, env.C.Records.Delete(ctx, mate, "notes", r.ID, &v, false), "forbidden")
	_, err := env.C.Records.Get(ctx, intern, "notes", r.ID)
	wantCode(t, err, "not_found")

	// App-wide: everyone in the app reads, only editors/admins edit.
	if err := env.C.Sharing.SetVisibility(ctx, eng, service.ResourceRef{Kind: "record", Collection: "notes", ID: r.ID}, "app", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := env.C.Records.Get(ctx, intern, "notes", r.ID); err != nil {
		t.Fatalf("viewer cannot read an app-wide record: %v", err)
	}
	_, err = env.C.Records.Update(ctx, intern, "notes", r.ID, in(`{"tag":"x"}`), v)
	wantCode(t, err, "forbidden")
	// Visibility to another app's team is not representable.
	wantCode(t, env.C.Sharing.SetVisibility(ctx, eng, service.ResourceRef{Kind: "record", Collection: "notes", ID: r.ID}, "team", "tm_nonexistent"), "validation_failed")
}

func TestGrantsAndShareSeparation(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	eng, mate, foreign := env.Ctx(t, "engineer@rel.test"), env.Ctx(t, "teammate@rel.test"), env.Ctx(t, "foreign@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "notes", in(`{"tag":"g"}`)))
	ref := service.ResourceRef{Kind: "record", Collection: "notes", ID: r.ID}
	// A viewer who may share, but not edit.
	g := must[*service.Grant](t)(env.C.Sharing.AddGrant(ctx, eng, ref, service.GrantInput{Subject: "teammate@rel.test", Role: "viewer", CanShare: true}))
	_, err := env.C.Records.Update(ctx, mate, "notes", r.ID, in(`{"tag":"x"}`), 1)
	wantCode(t, err, "forbidden")
	if _, err := env.C.Sharing.AddGrant(ctx, mate, ref, service.GrantInput{Subject: "foreign@rel.test", Role: "editor"}); err != nil {
		t.Fatalf("sharer could not share: %v", err)
	}
	// A sharer cannot hand out can_share (that is a manage right).
	_, err = env.C.Sharing.AddGrant(ctx, mate, ref, service.GrantInput{Subject: "intern@rel.test", Role: "viewer", CanShare: true})
	wantCode(t, err, "forbidden")
	if _, err := env.C.Records.Update(ctx, foreign, "notes", r.ID, in(`{"tag":"by foreign"}`), 1); err != nil {
		t.Fatalf("editor grant not honored: %v", err)
	}
	// Grants never reach outside the app.
	_, err = env.C.Sharing.AddGrant(ctx, eng, ref, service.GrantInput{Subject: "outsider@rel.test", Role: "viewer"})
	wantCode(t, err, "validation_failed")
	// Revocation applies to the next request.
	if err := env.C.Sharing.RemoveGrant(ctx, eng, ref, g.ID); err != nil {
		t.Fatal(err)
	}
	_, err = env.C.Records.Get(ctx, mate, "notes", r.ID)
	wantCode(t, err, "not_found")
	grants := must[[]service.Grant](t)(env.C.Sharing.Grants(ctx, eng, ref))
	if len(grants) != 1 || *grants[0].Subject != "foreign@rel.test" {
		t.Fatalf("grants %+v", grants)
	}
}

// Owning or being granted a resource never overrides CUI policy.
func TestSharingCannotOverrideClassification(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", service.RecordInput{Data: doc(`{"part_number":"A","status":"open"}`), Marking: &expt}))
	ref := service.ResourceRef{Kind: "record", Collection: "ncr", ID: r.ID}
	if _, err := env.C.Sharing.AddGrant(ctx, eng, ref, service.GrantInput{Subject: "foreign@rel.test", Role: "editor"}); err != nil {
		t.Fatal(err)
	}
	_, err := env.C.Records.Get(ctx, env.Ctx(t, "foreign@rel.test"), "ncr", r.ID)
	wantCode(t, err, "not_found") // NOFORN: a grant does not make a foreign national eligible
	if _, err := env.C.Sharing.AddGrant(ctx, eng, ref, service.GrantInput{Subject: "agent:assistant", Role: "editor"}); err != nil {
		t.Fatal(err)
	}
	v := must[*service.Record](t)(env.C.Records.Get(ctx, env.Ctx(t, "agent:assistant"), "ncr", r.ID))
	if !v.Withheld {
		t.Fatal("grant overrode the LLM boundary rule")
	}
}

func TestMembershipRevocationAndAdmins(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	admin, mate := env.Ctx(t, "admin@rel.test"), env.Ctx(t, "teammate@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, mate, "notes", in(`{"tag":"x"}`)))
	wantCode(t, env.C.Sharing.PutMember(ctx, mate, "intern@rel.test", "admin"), "forbidden")
	if err := env.C.Sharing.RemoveMember(ctx, admin, "teammate@rel.test"); err != nil {
		t.Fatal(err)
	}
	_, err := env.C.Records.Get(ctx, mate, "notes", r.ID)
	wantCode(t, err, "not_found") // removed members lose even their own records
	wantCode(t, env.C.Sharing.RemoveMember(ctx, admin, "admin@rel.test"), "conflict")
	wantCode(t, env.C.Sharing.PutMember(ctx, admin, "nobody@rel.test", "member"), "validation_failed")
	if err := env.C.Sharing.PutMember(ctx, admin, "teammate@rel.test", "member"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.C.Records.Get(ctx, mate, "notes", r.ID); err != nil {
		t.Fatalf("re-added member: %v", err)
	}
}

// Delegation: an actor must be a registered client of the app, and the effective permissions are
// the intersection of user and actor.
func TestDelegationInsideApps(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "notes", in(`{"tag":"x"}`)))
	obo := env.OnBehalf(t, "engineer@rel.test", "svc-mes@rel.test")
	if got, err := env.C.Records.Get(ctx, obo, "notes", r.ID); err != nil || got.Data["tag"] != "x" {
		t.Fatalf("registered client acting for the owner: %v", err)
	}
	env.Admin(t, `DELETE FROM app_clients WHERE subject = 'svc-mes@rel.test'`)
	_, err := env.C.Records.Get(ctx, obo, "notes", r.ID)
	wantCode(t, err, "not_found")
	// outsider is not a member: no client can act for them here.
	env.Admin(t, `INSERT INTO app_clients (app, subject, added_by) VALUES ($1, 'svc-mes@rel.test', 't')`, testenv.App)
	_, err = env.C.Records.Get(ctx, env.OnBehalf(t, "outsider@rel.test", "svc-mes@rel.test"), "notes", r.ID)
	wantCode(t, err, "not_found")
}

func TestWildcardDelegationDropsPrivilegedScopes(t *testing.T) {
	env := testenv.New(t)
	admin := env.Ctx(t, "admin@rel.test").Principal // scopes: *
	p := admin.DelegatedTo(admin)
	for _, s := range []string{"delegate", "principals:admin"} {
		if p.HasScope(s) {
			t.Fatalf("wildcard intersection restored %s", s)
		}
	}
	if !p.HasScope("records:read") {
		t.Fatal("wildcard intersection lost ordinary scopes")
	}
}

// The Go authorizer (used for precise errors and explanations) agrees with the RLS policies on a
// matrix of subjects x resources x operations.
func TestAuthorizerMatchesRLS(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	team := must[*service.Team](t)(env.C.Sharing.CreateTeam(ctx, eng, "crew"))
	_ = env.C.Sharing.PutTeamMember(ctx, eng, team.ID, "teammate@rel.test", "viewer")
	_ = env.C.Sharing.PutTeamMember(ctx, eng, team.ID, "foreign@rel.test", "admin")
	ids := map[string]string{}
	for _, spec := range []struct{ name, vis, team string }{{"private", "private", ""}, {"team", "team", team.ID}, {"app", "app", ""}, {"granted", "private", ""}} {
		r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "notes", service.RecordInput{Data: doc(`{"tag":"m"}`), Visibility: spec.vis, TeamID: spec.team}))
		ids[spec.name] = r.ID
	}
	ref := service.ResourceRef{Kind: "record", Collection: "notes", ID: ids["granted"]}
	_, _ = env.C.Sharing.AddGrant(ctx, eng, ref, service.GrantInput{Subject: "intern@rel.test", Role: "editor"})
	_, _ = env.C.Sharing.AddGrant(ctx, eng, ref, service.GrantInput{TeamID: team.ID, Role: "viewer", CanShare: true})

	db := store.NewDB(env.Runtime)
	for subject := range testenv.Members {
		for name, id := range ids {
			sc := store.Scope{App: testenv.App, Subject: subject, Actor: subject, Mode: store.ModeApp}
			var goPerm service.Perm
			var sqlRead, sqlWrite, sqlShare, sqlManage bool
			err := db.Run(ctx, sc, func(tx pgx.Tx) error {
				a := &service.Access{App: testenv.App, Subject: subject, Teams: map[string]string{}}
				if err := tx.QueryRow(ctx, `SELECT role FROM app_members WHERE app=$1 AND subject=$2`, testenv.App, subject).Scan(&a.Role); err != nil {
					return err
				}
				rows, _ := tx.Query(ctx, `SELECT team_id, role FROM team_members WHERE app=$1 AND subject=$2`, testenv.App, subject)
				for rows.Next() {
					var tm, role string
					_ = rows.Scan(&tm, &role)
					a.Teams[tm] = role
				}
				rows.Close()
				var owner, vis string
				var teamID *string
				if err := env.Migrator.QueryRow(ctx, `SELECT owner, visibility, team_id FROM records WHERE id=$1`, id).Scan(&owner, &vis, &teamID); err != nil {
					return err
				}
				res := service.Resource{Kind: "record", ID: id, Owner: owner, Visibility: vis}
				if teamID != nil {
					res.TeamID = *teamID
				}
				p, _, err := service.SQLAuthorizer{}.Permissions(ctx, tx, a, res)
				goPerm = p
				if err != nil {
					return err
				}
				_ = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM records WHERE id=$1)`, id).Scan(&sqlRead)
				_ = tx.QueryRow(ctx, `SELECT sb_can_manage(owner, visibility, team_id), sb_can_share('record', id, owner, visibility, team_id)
					FROM records WHERE id=$1`, id).Scan(&sqlManage, &sqlShare)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			// UPDATE visibility test in a rolled-back transaction.
			sqlWrite = db.Run(ctx, sc, func(tx pgx.Tx) error {
				tag, err := tx.Exec(ctx, `UPDATE records SET updated_at = now() WHERE id=$1`, id)
				if err == nil && tag.RowsAffected() == 1 {
					return errRollback
				}
				return fmt.Errorf("no update: %v", err)
			}) == errRollback
			want := fmt.Sprintf("read=%v write=%v share=%v manage=%v", sqlRead, sqlWrite, sqlShare && sqlRead, sqlManage && sqlRead)
			got := fmt.Sprintf("read=%v write=%v share=%v manage=%v", goPerm.Has(service.PermRead), goPerm.Has(service.PermWrite),
				goPerm.Has(service.PermShare), goPerm.Has(service.PermManage))
			if want != got {
				t.Errorf("%s on %s: RLS %s, authorizer %s", subject, name, want, got)
			}
		}
	}
}

var errRollback = fmt.Errorf("rollback")

func TestExplain(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng, admin := env.Ctx(t, "engineer@rel.test"), env.Ctx(t, "admin@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", service.RecordInput{Data: doc(`{"part_number":"A","status":"open"}`),
		Marking: &expt, Visibility: "app"}))
	ref := service.ResourceRef{Kind: "record", Collection: "ncr", ID: r.ID}
	ex := must[*service.Explanation](t)(env.C.Sharing.Explain(ctx, admin, "foreign@rel.test", ref))
	if ex.Allowed["read"] || ex.Policy["read"].Code != "noforn_requires_us_person" || strings.Join(ex.Permissions, ",") != "read" {
		t.Fatalf("foreign: %+v", ex)
	}
	ex = must[*service.Explanation](t)(env.C.Sharing.Explain(ctx, admin, "agent:assistant", ref))
	if !ex.Allowed["read"] || ex.Allowed["read_content"] || ex.Policy["read_content"].Code != "llm_boundary_not_authorized" {
		t.Fatalf("agent: %+v", ex)
	}
	ex = must[*service.Explanation](t)(env.C.Sharing.Explain(ctx, admin, "outsider@rel.test", ref))
	if len(ex.Sharing) != 1 || ex.Sharing[0] != "not_app_member" {
		t.Fatalf("outsider: %+v", ex)
	}
	// Only app admins may ask; a private resource the admin cannot see is not described.
	_, err := env.C.Sharing.Explain(ctx, eng, "foreign@rel.test", ref)
	wantCode(t, err, "forbidden")
	p := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", service.RecordInput{Data: doc(`{"part_number":"B","status":"open"}`)}))
	_, err = env.C.Sharing.Explain(ctx, admin, "engineer@rel.test", service.ResourceRef{Kind: "record", Collection: "ncr", ID: p.ID})
	wantCode(t, err, "not_found")
	if !strings.Contains(err.Error(), "resource_not_visible_to_caller") {
		t.Fatalf("reason code: %v", err)
	}
	names := []string{}
	for k := range ex.Policy {
		names = append(names, k)
	}
	sort.Strings(names)
	_ = names
}
