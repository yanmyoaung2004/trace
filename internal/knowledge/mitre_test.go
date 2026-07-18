package knowledge_test

import (
	"testing"

	"github.com/yanmyoaung2004/innoigniter-ai/internal/knowledge"
)

func TestMitreDBSearch(t *testing.T) {
	db, err := knowledge.LoadMitreSeed()
	if err != nil {
		t.Fatalf("LoadMitreSeed failed: %v", err)
	}

	t1 := db.GetByID("T1566")
	if t1 == nil {
		t.Fatal("T1566 not found")
	}
	if t1.Name != "Phishing" {
		t.Fatalf("expected Phishing, got %s", t1.Name)
	}
}

func TestMitreDBSearchBySubtechnique(t *testing.T) {
	db, _ := knowledge.LoadMitreSeed()

	t1 := db.GetByID("T1566.001")
	if t1 == nil {
		t.Fatal("T1566.001 not found")
	}
	if t1.Name != "Spearphishing Attachment" {
		t.Fatalf("expected Spearphishing Attachment, got %s", t1.Name)
	}
}

func TestMitreDBSearchByKeyword(t *testing.T) {
	db, _ := knowledge.LoadMitreSeed()

	results := db.Search("phishing")
	if len(results) == 0 {
		t.Fatal("expected phishing results")
	}
}

func TestMitreDBGetByTactic(t *testing.T) {
	db, _ := knowledge.LoadMitreSeed()

	results := db.GetByTactic("initial-access")
	if len(results) == 0 {
		t.Fatal("expected initial-access techniques")
	}
}

func TestMitreDBMissing(t *testing.T) {
	db, _ := knowledge.LoadMitreSeed()

	t1 := db.GetByID("T9999")
	if t1 != nil {
		t.Fatal("expected nil for missing technique")
	}
}
