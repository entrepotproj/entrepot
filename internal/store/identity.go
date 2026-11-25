package store

import (
	"context"
	"encoding/json"
	"time"
)

type User struct {
	ID          string     `json:"id"`
	Issuer      string     `json:"issuer"`
	Subject     string     `json:"subject"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	DisplayName string     `json:"displayName"`
	GivenName   string     `json:"givenName"`
	Groups      []string   `json:"groups"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
}

const userCols = `id, issuer, subject, username, email, display_name, given_name, groups, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Username, &u.Email, &u.DisplayName, &u.GivenName, &u.Groups, &u.CreatedAt, &u.LastLoginAt)
	return &u, err
}

// UpsertUser records a user seen via OIDC (login or bearer token).
func (s *Store) UpsertUser(ctx context.Context, u *User, login bool) (*User, error) {
	if u.Groups == nil {
		u.Groups = []string{}
	}
	out, err := scanUser(s.pool.QueryRow(ctx, `INSERT INTO users (issuer, subject, username, email, display_name, given_name, groups, last_login_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7, CASE WHEN $8 THEN now() END)
		ON CONFLICT (issuer, subject) DO UPDATE SET username=EXCLUDED.username, email=EXCLUDED.email,
			display_name=EXCLUDED.display_name, given_name=EXCLUDED.given_name, groups=EXCLUDED.groups,
			last_login_at = CASE WHEN $8 THEN now() ELSE users.last_login_at END
		RETURNING `+userCols, u.Issuer, u.Subject, u.Username, u.Email, u.DisplayName, u.GivenName, u.Groups, login))
	return out, mapErr(err, "upsert user")
}

func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
	return u, mapErr(err, "user")
}

func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, mapErr(err, "list users")
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type APIToken struct {
	ID         string     `json:"id"`
	UserID     string     `json:"userId"`
	Name       string     `json:"name"`
	Hint       string     `json:"hint"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

const tokenCols = `id, user_id, name, hint, scopes, expires_at, last_used_at, created_at`

func scanToken(row interface{ Scan(...any) error }) (*APIToken, error) {
	var t APIToken
	err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Hint, &t.Scopes, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt)
	return &t, err
}

func (s *Store) CreateAPIToken(ctx context.Context, t *APIToken, hash []byte) (*APIToken, error) {
	if t.Scopes == nil {
		t.Scopes = []string{}
	}
	out, err := scanToken(s.pool.QueryRow(ctx, `INSERT INTO api_tokens (user_id, name, hint, hash, scopes, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+tokenCols, t.UserID, t.Name, t.Hint, hash, t.Scopes, t.ExpiresAt))
	return out, mapErr(err, "create token")
}

// LookupAPIToken finds a non-expired token by hash and returns it with its user.
func (s *Store) LookupAPIToken(ctx context.Context, hash []byte) (*APIToken, *User, error) {
	row := s.pool.QueryRow(ctx, `SELECT t.id, t.user_id, t.name, t.hint, t.scopes, t.expires_at, t.last_used_at, t.created_at,
		u.id, u.issuer, u.subject, u.username, u.email, u.display_name, u.given_name, u.groups, u.created_at, u.last_login_at
		FROM api_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.hash=$1 AND (t.expires_at IS NULL OR t.expires_at > now())`, hash)
	var t APIToken
	var u User
	err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Hint, &t.Scopes, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt,
		&u.ID, &u.Issuer, &u.Subject, &u.Username, &u.Email, &u.DisplayName, &u.GivenName, &u.Groups, &u.CreatedAt, &u.LastLoginAt)
	if err != nil {
		return nil, nil, mapErr(err, "token")
	}
	return &t, &u, nil
}

func (s *Store) TouchAPIToken(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at=now()
		WHERE id=$1 AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')`, id)
}

func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]*APIToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+tokenCols+` FROM api_tokens WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, mapErr(err, "list tokens")
	}
	defer rows.Close()
	out := []*APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAPIToken(ctx context.Context, userID, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM api_tokens WHERE id=$1 AND user_id=$2`, id, userID)
	if err != nil {
		return mapErr(err, "delete token")
	}
	if tag.RowsAffected() == 0 {
		return mapErr(errNoRows, "token")
	}
	return nil
}

type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Actions     []string  `json:"actions"`
	Builtin     bool      `json:"builtin"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

const roleCols = `id, name, description, actions, builtin, created_at, updated_at`

func scanRole(row interface{ Scan(...any) error }) (*Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Actions, &r.Builtin, &r.CreatedAt, &r.UpdatedAt)
	return &r, err
}

func (s *Store) ListRoles(ctx context.Context) ([]*Role, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+roleCols+` FROM roles ORDER BY builtin DESC, name`)
	if err != nil {
		return nil, mapErr(err, "list roles")
	}
	defer rows.Close()
	out := []*Role{}
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRole(ctx context.Context, name string) (*Role, error) {
	r, err := scanRole(s.pool.QueryRow(ctx, `SELECT `+roleCols+` FROM roles WHERE name=$1`, name))
	return r, mapErr(err, "role "+name)
}

func (s *Store) CreateRole(ctx context.Context, r *Role) (*Role, error) {
	out, err := scanRole(s.pool.QueryRow(ctx, `INSERT INTO roles (name, description, actions) VALUES ($1,$2,$3) RETURNING `+roleCols,
		r.Name, r.Description, r.Actions))
	return out, mapErr(err, "create role "+r.Name)
}

func (s *Store) UpdateRole(ctx context.Context, r *Role) (*Role, error) {
	out, err := scanRole(s.pool.QueryRow(ctx, `UPDATE roles SET description=$2, actions=$3, updated_at=now()
		WHERE name=$1 AND NOT builtin RETURNING `+roleCols, r.Name, r.Description, r.Actions))
	return out, mapErr(err, "update role "+r.Name+" (built-in roles are read-only)")
}

func (s *Store) DeleteRole(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM roles WHERE name=$1 AND NOT builtin`, name)
	if err != nil {
		return mapErr(err, "delete role")
	}
	if tag.RowsAffected() == 0 {
		return mapErr(errNoRows, "role "+name+" (built-in roles cannot be deleted)")
	}
	return nil
}

type RoleBinding struct {
	ID                string    `json:"id"`
	Role              string    `json:"role"`
	SubjectType       string    `json:"subjectType"`
	Subject           string    `json:"subject"`
	RepositoryPattern string    `json:"repositoryPattern"`
	Actions           []string  `json:"actions"`
	CreatedAt         time.Time `json:"createdAt"`
}

func (s *Store) ListRoleBindings(ctx context.Context) ([]*RoleBinding, error) {
	rows, err := s.pool.Query(ctx, `SELECT b.id, r.name, b.subject_type, b.subject, b.repository_pattern, r.actions, b.created_at
		FROM role_bindings b JOIN roles r ON r.id=b.role_id ORDER BY b.created_at`)
	if err != nil {
		return nil, mapErr(err, "list role bindings")
	}
	defer rows.Close()
	out := []*RoleBinding{}
	for rows.Next() {
		var b RoleBinding
		if err := rows.Scan(&b.ID, &b.Role, &b.SubjectType, &b.Subject, &b.RepositoryPattern, &b.Actions, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

func (s *Store) CreateRoleBinding(ctx context.Context, b *RoleBinding) (*RoleBinding, error) {
	var id string
	err := s.pool.QueryRow(ctx, `INSERT INTO role_bindings (role_id, subject_type, subject, repository_pattern)
		VALUES ((SELECT id FROM roles WHERE name=$1),$2,$3,$4) RETURNING id`,
		b.Role, b.SubjectType, b.Subject, b.RepositoryPattern).Scan(&id)
	if err != nil {
		if isNotNullViolation(err) {
			return nil, mapErr(errNoRows, "role "+b.Role)
		}
		return nil, mapErr(err, "create role binding")
	}
	all, err := s.ListRoleBindings(ctx)
	if err != nil {
		return nil, err
	}
	for _, x := range all {
		if x.ID == id {
			return x, nil
		}
	}
	return nil, mapErr(errNoRows, "role binding")
}

func (s *Store) DeleteRoleBinding(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM role_bindings WHERE id=$1`, id)
	if err != nil {
		return mapErr(err, "delete role binding")
	}
	if tag.RowsAffected() == 0 {
		return mapErr(errNoRows, "role binding")
	}
	return nil
}

type GitLabTrustPolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	GitLab      string            `json:"gitlab"`
	Conditions  map[string]string `json:"conditions"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
}

const policyCols = `id, name, description, gitlab, conditions, created_at, updated_at`

func scanPolicy(row interface{ Scan(...any) error }) (*GitLabTrustPolicy, error) {
	var p GitLabTrustPolicy
	var cond []byte
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.GitLab, &cond, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.Conditions = map[string]string{}
	_ = json.Unmarshal(cond, &p.Conditions)
	return &p, nil
}

func (s *Store) ListGitLabTrustPolicies(ctx context.Context) ([]*GitLabTrustPolicy, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+policyCols+` FROM gitlab_trust_policies ORDER BY name`)
	if err != nil {
		return nil, mapErr(err, "list trust policies")
	}
	defer rows.Close()
	out := []*GitLabTrustPolicy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetGitLabTrustPolicy(ctx context.Context, name string) (*GitLabTrustPolicy, error) {
	p, err := scanPolicy(s.pool.QueryRow(ctx, `SELECT `+policyCols+` FROM gitlab_trust_policies WHERE name=$1`, name))
	return p, mapErr(err, "trust policy "+name)
}

func (s *Store) CreateGitLabTrustPolicy(ctx context.Context, p *GitLabTrustPolicy) (*GitLabTrustPolicy, error) {
	cond, _ := json.Marshal(p.Conditions)
	out, err := scanPolicy(s.pool.QueryRow(ctx, `INSERT INTO gitlab_trust_policies (name, description, gitlab, conditions)
		VALUES ($1,$2,$3,$4) RETURNING `+policyCols, p.Name, p.Description, p.GitLab, cond))
	return out, mapErr(err, "create trust policy "+p.Name)
}

func (s *Store) UpdateGitLabTrustPolicy(ctx context.Context, p *GitLabTrustPolicy) (*GitLabTrustPolicy, error) {
	cond, _ := json.Marshal(p.Conditions)
	out, err := scanPolicy(s.pool.QueryRow(ctx, `UPDATE gitlab_trust_policies SET description=$2, gitlab=$3, conditions=$4, updated_at=now()
		WHERE name=$1 RETURNING `+policyCols, p.Name, p.Description, p.GitLab, cond))
	return out, mapErr(err, "update trust policy "+p.Name)
}

// DeleteGitLabTrustPolicy deletes the policy and any role bindings that reference it.
func (s *Store) DeleteGitLabTrustPolicy(ctx context.Context, name string) error {
	return s.inTx(ctx, func(tx pgxTx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM gitlab_trust_policies WHERE name=$1`, name)
		if err != nil {
			return mapErr(err, "delete trust policy")
		}
		if tag.RowsAffected() == 0 {
			return mapErr(errNoRows, "trust policy "+name)
		}
		_, err = tx.Exec(ctx, `DELETE FROM role_bindings WHERE subject_type='gitlab_policy' AND subject=$1`, name)
		return mapErr(err, "delete trust policy bindings")
	})
}

type AuditEvent struct {
	ID       int64           `json:"id"`
	At       time.Time       `json:"at"`
	Actor    string          `json:"actor"`
	Action   string          `json:"action"`
	Target   string          `json:"target"`
	Details  json.RawMessage `json:"details"`
	RemoteIP string          `json:"remoteIp"`
}

func (s *Store) Audit(ctx context.Context, e AuditEvent) error {
	if e.Details == nil {
		e.Details = json.RawMessage(`{}`)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_events (actor, action, target, details, remote_ip) VALUES ($1,$2,$3,$4,$5)`,
		e.Actor, e.Action, e.Target, e.Details, e.RemoteIP)
	return mapErr(err, "audit")
}

func (s *Store) ListAuditEvents(ctx context.Context, beforeID int64, limit int) ([]*AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if beforeID <= 0 {
		beforeID = 1<<63 - 1
	}
	rows, err := s.pool.Query(ctx, `SELECT id, at, actor, action, target, details, remote_ip FROM audit_events
		WHERE id < $1 ORDER BY id DESC LIMIT $2`, beforeID, limit)
	if err != nil {
		return nil, mapErr(err, "list audit events")
	}
	defer rows.Close()
	out := []*AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &e.Details, &e.RemoteIP); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

type DockerUpload struct {
	ID           string    `json:"id"`
	RepositoryID string    `json:"repositoryId"`
	Image        string    `json:"image"`
	Size         int64     `json:"size"`
	Chunks       int       `json:"chunks"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

func (s *Store) CreateDockerUpload(ctx context.Context, repoID, image string) (*DockerUpload, error) {
	var u DockerUpload
	err := s.pool.QueryRow(ctx, `INSERT INTO docker_uploads (repository_id, image) VALUES ($1,$2)
		RETURNING id, repository_id, image, size, chunks, created_at, updated_at`, repoID, image).
		Scan(&u.ID, &u.RepositoryID, &u.Image, &u.Size, &u.Chunks, &u.CreatedAt, &u.UpdatedAt)
	return &u, mapErr(err, "create upload")
}

func (s *Store) GetDockerUpload(ctx context.Context, repoID, id string) (*DockerUpload, error) {
	var u DockerUpload
	err := s.pool.QueryRow(ctx, `SELECT id, repository_id, image, size, chunks, created_at, updated_at
		FROM docker_uploads WHERE id=$1 AND repository_id=$2`, id, repoID).
		Scan(&u.ID, &u.RepositoryID, &u.Image, &u.Size, &u.Chunks, &u.CreatedAt, &u.UpdatedAt)
	return &u, mapErr(err, "upload "+id)
}

// AdvanceDockerUpload records an appended chunk, guarding against concurrent
// or out-of-order PATCHes via the expected chunk number.
func (s *Store) AdvanceDockerUpload(ctx context.Context, id string, expectChunks int, added int64) (*DockerUpload, error) {
	var u DockerUpload
	err := s.pool.QueryRow(ctx, `UPDATE docker_uploads SET size=size+$3, chunks=chunks+1, updated_at=now()
		WHERE id=$1 AND chunks=$2 RETURNING id, repository_id, image, size, chunks, created_at, updated_at`,
		id, expectChunks, added).Scan(&u.ID, &u.RepositoryID, &u.Image, &u.Size, &u.Chunks, &u.CreatedAt, &u.UpdatedAt)
	return &u, mapErr(err, "advance upload")
}

func (s *Store) DeleteDockerUpload(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM docker_uploads WHERE id=$1`, id)
	return mapErr(err, "delete upload")
}

// StaleDockerUploads returns uploads not touched for longer than age.
func (s *Store) StaleDockerUploads(ctx context.Context, age time.Duration) ([]*DockerUpload, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, repository_id, image, size, chunks, created_at, updated_at
		FROM docker_uploads WHERE updated_at < now() - make_interval(secs => $1) LIMIT 500`, age.Seconds())
	if err != nil {
		return nil, mapErr(err, "stale uploads")
	}
	defer rows.Close()
	var out []*DockerUpload
	for rows.Next() {
		var u DockerUpload
		if err := rows.Scan(&u.ID, &u.RepositoryID, &u.Image, &u.Size, &u.Chunks, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &u)
	}
	return out, rows.Err()
}

func (s *Store) GetUserByIssuerSubject(ctx context.Context, issuer, subject string) (*User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE issuer=$1 AND subject=$2`, issuer, subject))
	return u, mapErr(err, "user")
}

func (s *Store) ListUsersByIssuer(ctx context.Context, issuer string) ([]*User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users WHERE issuer=$1 ORDER BY username`, issuer)
	if err != nil {
		return nil, mapErr(err, "list users")
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, u *User) (*User, error) {
	if u.Groups == nil {
		u.Groups = []string{}
	}
	out, err := scanUser(s.pool.QueryRow(ctx, `INSERT INTO users (issuer, subject, username, email, display_name, given_name, groups)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+userCols, u.Issuer, u.Subject, u.Username, u.Email, u.DisplayName, u.GivenName, u.Groups))
	return out, mapErr(err, "create user "+u.Username)
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return mapErr(err, "delete user")
	}
	if tag.RowsAffected() == 0 {
		return mapErr(errNoRows, "user")
	}
	return nil
}
