package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tableHeader = "| ID | Section | Level | Requirement | Tests |\n|----|---------|-------|-------------|-------|\n"

// TestReadmeChecklistBadge uses the checker itself so n/a requirements are
// counted in the denominator, and only validated test mappings in the numerator.
func TestReadmeChecklistBadge(t *testing.T) {
	root := filepath.Join("..", "..")
	file := filepath.Join(root, "CHECKLIST.md")
	var out bytes.Buffer
	if code := run([]string{"-file", file, root}, &out, &out); code != 0 {
		t.Fatalf("invalid repository checklist (exit %d):\n%s", code, out.String())
	}
	items, err := parseChecklist(file, func(format string, args ...any) {
		t.Errorf(format, args...)
	})
	if err != nil {
		t.Fatal(err)
	}
	mapped := 0
	for _, it := range items {
		if !it.na {
			mapped++
		}
	}
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("[![Checklist: %d/%d mapped](https://img.shields.io/badge/checklist-%d%%2F%d%%20mapped-blue)](CHECKLIST.md)",
		mapped, len(items), mapped, len(items))
	if strings.Count(string(readme), want) != 1 {
		t.Errorf("README must contain exactly one current checklist badge:\n%s", want)
	}
}

// fixture writes a checklist and one test file into a new directory and runs
// the check there. It returns the exit code and the combined output.
func fixture(t *testing.T, checklist, tests string, args ...string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "CHECKLIST.md"), []byte(checklist), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte("package x\n\n"+tests), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args = append([]string{"-file", filepath.Join(dir, "CHECKLIST.md")}, args...)
	if len(args) == 2 {
		args = append(args, dir)
	}
	code := run(args, &out, &out)
	return code, out.String()
}

func TestValidChecklist(t *testing.T) {
	checklist := "# Title\n\nSome text | with a pipe.\n\n| Other | table |\n|---|---|\n| X-1 | ignored |\n\n" + tableHeader +
		"| ABC-DEF-01 | 4.1 | MUST | Do a thing. | `TestA`, TestB |\n" +
		"| ABC-DEF-02 | 4.2 | SHOULD NOT | Do another. | n/a: the caller does it. |\n" +
		"\n" + tableHeader +
		"| ABC-XYZ-10 | 5 | Normative | A third. | `FuzzC`, `TestB` |\n"
	tests := "// TestA covers one.\n//\n// checklist: ABC-DEF-01\nfunc TestA(t *testing.T) {}\n\n" +
		"// checklist: ABC-DEF-01, ABC-XYZ-10\nfunc TestB(t *testing.T) {}\n\n" +
		"// checklist: ABC-XYZ-10\nfunc FuzzC(f *testing.F) {}\n\n" +
		"func Example() {}\n\nfunc helper() {}\n\ntype T struct{}\n\nfunc (T) TestMethod() {}\n"
	code, out := fixture(t, checklist, tests)
	if code != 0 || !strings.Contains(out, "3 items (2 mapped to tests, 1 not applicable), 4 tests") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestChecklistProblems(t *testing.T) {
	checklist := tableHeader +
		"| ABC-01 | 1 | MUST | Mapped to a missing test. | TestMissing |\n" +
		"| ABC-01 | 1 | MUST | Duplicate ID. | TestA |\n" +
		"| abc-02 | 1 | MUST | Bad ID. | TestA |\n" +
		"| ABC-03 | | MUST | No section. | TestA |\n" +
		"| ABC-04 | 1 | PROBABLY | Bad level. | TestA |\n" +
		"| ABC-05 | 1 | MUST |  | TestA |\n" +
		"| ABC-06 | 1 | MUST | No tests. |  |\n" +
		"| ABC-07 | 1 | MUST | N/A without a reason. | n/a: |\n" +
		"| ABC-08 | 1 | MUST | Not a test name. | helper |\n" +
		"| ABC-09 | 1 | MUST | Too few cells. |\n" +
		"| ABC-10 | 1 | MUST | Test does not name it. | TestA |\n" +
		"| ABC-11 | 1 | MUST | Not applicable. | n/a: reasons. |\n"
	tests := "// checklist: ABC-03 ABC-04 ABC-05\nfunc TestA(t *testing.T) {}\n\n" +
		"func TestUnnamed(t *testing.T) {}\n\n" +
		"// checklist: ABC-99 ABC-11 ABC-03\nfunc TestB(t *testing.T) {}\n"
	code, out := fixture(t, checklist, tests)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	for _, want := range []string{
		"ABC-01 lists TestMissing, which is not a test",
		"ABC-01 is already used on line 3",
		`"abc-02" is not an item ID`,
		"ABC-03 has no RFC section",
		`ABC-04 has level "PROBABLY"`,
		"ABC-05 states no requirement",
		"ABC-06 names no test",
		"ABC-07 is not applicable but gives no reason",
		`ABC-08 lists "helper", which is not a test function name`,
		"row has 4 cells, want 5",
		"TestA does not name ABC-10, which lists it",
		"TestUnnamed names no checklist item",
		"TestB names ABC-99, which is not in",
		"TestB names ABC-11, which is not applicable",
		"ABC-03 does not list TestB, which names it",
		"problem(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestDuplicateTestNames(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
		src := "package " + sub + "\n\n// checklist: ABC-01\nfunc TestA(t *testing.T) {}\n"
		if err := os.WriteFile(filepath.Join(dir, sub, "a_test.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(dir, "CHECKLIST.md")
	if err := os.WriteFile(file, []byte(tableHeader+"| ABC-01 | 1 | MUST | One. | TestA |\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := run([]string{"-file", file, filepath.Join(dir, "a"), filepath.Join(dir, "b")}, &out, &out); code != 1 || !strings.Contains(out.String(), "TestA is also defined at") {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
}

func TestRunErrors(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"-nosuchflag"}, &out, &out); code != 2 {
		t.Errorf("bad flag: exit %d", code)
	}
	if code := run([]string{"-file", filepath.Join(t.TempDir(), "missing.md")}, &out, &out); code != 2 {
		t.Errorf("missing checklist: exit %d", code)
	}
	if code, out := fixture(t, tableHeader, "func Broken( {"); code != 2 {
		t.Errorf("unparsable test file: exit %d\n%s", code, out)
	}
	if code, out := fixture(t, tableHeader, "", "a["); code != 2 {
		t.Errorf("bad directory pattern: exit %d\n%s", code, out)
	}
}

func TestDefaultDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "CHECKLIST.md"), []byte(tableHeader+"| ABC-01 | 1 | MUST | One. | n/a: none. |\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	var out bytes.Buffer
	if code := run(nil, &out, &out); code != 0 || !strings.Contains(out.String(), "1 items (0 mapped to tests, 1 not applicable), 0 tests") {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
}
