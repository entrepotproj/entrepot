package signing_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/jackc/pgx/v5"

	"github.com/geoffo-dev/package-repository/internal/db"
	"github.com/geoffo-dev/package-repository/internal/secrets"
	"github.com/geoffo-dev/package-repository/internal/signing"
	"github.com/geoffo-dev/package-repository/internal/store"
)

// setup creates a fresh database with one repository and returns its ID.
func setup(t *testing.T) (*store.Store, *secrets.Box, string) {
	t.Helper()
	admin := os.Getenv("ENTREPOT_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("ENTREPOT_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "entrepot_test_sign_" + hex.EncodeToString(b)
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	u, _ := url.Parse(admin)
	u.Path = "/" + name
	pool, err := db.Open(ctx, u.String(), 5)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if c, err := pgx.Connect(context.Background(), admin); err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(context.Background())
		}
	})
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	if _, err := st.CreateBlobStore(ctx, &store.BlobStore{Name: "default", Type: "file", Config: []byte(`{"path":"/tmp/x"}`)}); err != nil {
		t.Fatal(err)
	}
	r, err := st.CreateRepository(ctx, &store.Repository{Name: "debs", Format: "apt", Kind: "hosted", BlobStoreName: "default",
		Online: true, Config: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	box, err := secrets.New(strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	return st, box, r.ID
}

func keyring(t *testing.T, k *signing.Key) openpgp.EntityList {
	t.Helper()
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(k.PublicArmored))
	if err != nil {
		t.Fatal(err)
	}
	bin, err := k.PublicBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.ReadKeyRing(bytes.NewReader(bin)); err != nil {
		t.Fatal(err)
	}
	return el
}

func verify(t *testing.T, svc *signing.Service, repoID string, kr openpgp.EntityList) {
	t.Helper()
	ctx := context.Background()
	data := []byte("Origin: test\nSuite: stable\n")
	in, err := svc.ClearSign(ctx, repoID, data)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := clearsign.Decode(in)
	if b == nil {
		t.Fatalf("not clearsigned: %s", in)
	}
	if _, err := b.VerifySignature(kr, nil); err != nil {
		t.Fatalf("clearsign: %v", err)
	}
	for _, armored := range []bool{false, true} {
		sig, err := svc.DetachSign(ctx, repoID, data, armored)
		if err != nil {
			t.Fatal(err)
		}
		if armored {
			_, err = openpgp.CheckArmoredDetachedSignature(kr, bytes.NewReader(data), bytes.NewReader(sig), nil)
		} else {
			_, err = openpgp.CheckDetachedSignature(kr, bytes.NewReader(data), bytes.NewReader(sig), nil)
		}
		if err != nil {
			t.Fatalf("detached (armored=%v): %v", armored, err)
		}
	}
}

func TestLifecycle(t *testing.T) {
	st, box, repoID := setup(t)
	ctx := context.Background()
	svc := signing.New(st, box) // default RSA-4096
	k, err := svc.ActiveKey(ctx, repoID)
	if err != nil {
		t.Fatal(err)
	}
	if k.Algorithm != "rsa4096" || len(k.Fingerprint) != 40 {
		t.Fatalf("key: %s %s", k.Algorithm, k.Fingerprint)
	}
	kr := keyring(t, k)
	if id := kr[0].PrimaryIdentity(); id == nil || !strings.Contains(id.Name, "Entrepot debs") {
		t.Fatalf("identity: %+v", kr[0].Identities)
	}
	verify(t, svc, repoID, kr)

	// The private key is sealed at rest.
	row, err := st.GetActiveSigningKey(ctx, repoID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row.PrivateSealed, "enc:v1:") {
		t.Fatalf("private key not sealed: %.40s", row.PrivateSealed)
	}

	// A second replica sees the same key; rotation is visible to it.
	replica := signing.New(st, box)
	replica.RSABits = 2048
	k2, err := replica.ActiveKey(ctx, repoID)
	if err != nil || k2.Fingerprint != k.Fingerprint {
		t.Fatalf("replica key %v %v", k2, err)
	}
	svc.RSABits = 2048
	rot, err := svc.Rotate(ctx, repoID)
	if err != nil {
		t.Fatal(err)
	}
	if rot.Fingerprint == k.Fingerprint || rot.Algorithm != "rsa2048" {
		t.Fatalf("rotated: %+v", rot)
	}
	k3, err := replica.ActiveKey(ctx, repoID)
	if err != nil || k3.Fingerprint != rot.Fingerprint {
		t.Fatalf("replica did not pick up rotation: %v %v", k3, err)
	}
	verify(t, replica, repoID, keyring(t, rot))
	keys, _ := st.ListSigningKeys(ctx, repoID)
	if len(keys) != 2 || !keys[0].Active || keys[1].Active {
		t.Fatalf("keys: %+v", keys)
	}
}

func TestImport(t *testing.T) {
	st, box, repoID := setup(t)
	ctx := context.Background()
	svc := signing.New(st, box)

	e, err := openpgp.NewEntity("Acme Repo", "", "repo@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.EncryptPrivateKeys([]byte("s3cret"), nil); err != nil {
		t.Fatal(err)
	}
	var priv bytes.Buffer
	w, _ := armor.Encode(&priv, openpgp.PrivateKeyType, nil)
	_ = e.SerializePrivateWithoutSigning(w, nil)
	_ = w.Close()
	var pub bytes.Buffer
	w, _ = armor.Encode(&pub, openpgp.PublicKeyType, nil)
	_ = e.Serialize(w)
	_ = w.Close()

	for _, tc := range []struct{ key, pass string }{
		{"garbage", ""}, {pub.String(), ""}, {priv.String(), ""}, {priv.String(), "wrong"},
	} {
		if _, err := svc.Import(ctx, repoID, tc.key, tc.pass); !errors.Is(err, signing.ErrInvalidKey) {
			t.Fatalf("import (pass %q) err = %v, want ErrInvalidKey", tc.pass, err)
		}
	}
	k, err := svc.Import(ctx, repoID, priv.String(), "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
	if k.Fingerprint != want || k.Algorithm != "ed25519" {
		t.Fatalf("imported %s %s, want %s", k.Fingerprint, k.Algorithm, want)
	}
	// Signatures from a fresh service (reopened from the database) verify
	// with the original public key.
	kr, _ := openpgp.ReadArmoredKeyRing(&pub)
	verify(t, signing.New(st, box), repoID, kr)
}
