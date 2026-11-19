package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// RoutingRule is a stored routing rule: regular expressions matched against
// the subject (package/image name or path) of proxy upstream requests.
type RoutingRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Mode        string    `json:"mode"`
	Matchers    []string  `json:"matchers"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

const routingRuleCols = `id, name, description, mode, matchers, created_at, updated_at`

func scanRoutingRule(row interface{ Scan(...any) error }) (*RoutingRule, error) {
	var r RoutingRule
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Mode, &r.Matchers, &r.CreatedAt, &r.UpdatedAt)
	if r.Matchers == nil {
		r.Matchers = []string{}
	}
	return &r, err
}

func (s *Store) ListRoutingRules(ctx context.Context) ([]*RoutingRule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+routingRuleCols+` FROM routing_rules ORDER BY name`)
	if err != nil {
		return nil, mapErr(err, "list routing rules")
	}
	defer rows.Close()
	out := []*RoutingRule{}
	for rows.Next() {
		r, err := scanRoutingRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRoutingRule(ctx context.Context, name string) (*RoutingRule, error) {
	r, err := scanRoutingRule(s.pool.QueryRow(ctx, `SELECT `+routingRuleCols+` FROM routing_rules WHERE name=$1`, name))
	return r, mapErr(err, "routing rule "+name)
}

func (s *Store) CreateRoutingRule(ctx context.Context, r *RoutingRule) (*RoutingRule, error) {
	out, err := scanRoutingRule(s.pool.QueryRow(ctx, `INSERT INTO routing_rules (name, description, mode, matchers)
		VALUES ($1,$2,$3,$4) RETURNING `+routingRuleCols, r.Name, r.Description, r.Mode, r.Matchers))
	return out, mapErr(err, "create routing rule "+r.Name)
}

func (s *Store) UpdateRoutingRule(ctx context.Context, r *RoutingRule) (*RoutingRule, error) {
	out, err := scanRoutingRule(s.pool.QueryRow(ctx, `UPDATE routing_rules SET description=$2, mode=$3, matchers=$4,
		updated_at=now() WHERE name=$1 RETURNING `+routingRuleCols, r.Name, r.Description, r.Mode, r.Matchers))
	return out, mapErr(err, "routing rule "+r.Name)
}

// DeleteRoutingRule deletes a rule unless a proxy repository still uses it
// (ErrInUse).
func (s *Store) DeleteRoutingRule(ctx context.Context, name string) error {
	users, err := s.RepositoriesUsingRoutingRule(ctx, name)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return errInUse("routing rule "+name, users)
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM routing_rules t WHERE t.name=$1 AND NOT EXISTS
		(SELECT 1 FROM repositories r WHERE r.config->'proxy'->>'routingRule' = t.name)`, name)
	if err != nil {
		return mapErr(err, "delete routing rule "+name)
	}
	if tag.RowsAffected() == 0 {
		if ok, _ := s.NamedExists(ctx, "routing_rules", name); ok {
			return errInUse("routing rule "+name, nil)
		}
		return mapErr(errNoRows, "routing rule "+name)
	}
	return nil
}

// RepositoriesUsingRoutingRule lists proxy repositories configured with the rule.
func (s *Store) RepositoriesUsingRoutingRule(ctx context.Context, name string) ([]string, error) {
	return s.repoNames(ctx, `SELECT name FROM repositories WHERE config->'proxy'->>'routingRule' = $1 ORDER BY name`, name)
}

func errInUse(what string, users []string) error {
	if len(users) == 0 {
		return fmt.Errorf("%s: %w", what, ErrInUse)
	}
	return fmt.Errorf("%s is used by repositories %s: %w", what, strings.Join(users, ", "), ErrInUse)
}
