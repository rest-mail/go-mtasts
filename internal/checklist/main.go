// Command checklist checks that an RFC checklist and the tests agree.
//
// The checklist is a Markdown file (CHECKLIST.md by default) holding one or
// more tables whose header is exactly
//
//	| ID | Section | Level | Requirement | Tests |
//
// Each row of such a table is one requirement:
//
//   - ID is unique, upper case, and ends in a number: SPF-EVAL-04.
//   - Section is the RFC section, for example 4.6.4.
//   - Level is the RFC 2119 keyword the requirement carries (MUST, MUST NOT,
//     SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY, ...), or
//     "Normative" for normative text without a keyword.
//   - Requirement says what is required, in one line.
//   - Tests lists the test functions that cover it, separated by commas
//     (backticks optional), or says "n/a: " and why it does not apply.
//
// A test names the items it covers with a line in its doc comment:
//
//	// checklist: SPF-EVAL-04 SPF-EVAL-05
//
// The check fails when an ID is used twice, an item names no test, an item and
// a test disagree about each other, a test names an unknown or not-applicable
// item, or a Test or Fuzz function names no item. Example functions may name
// items but need not.
//
// Usage:
//
//	go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]
//
// The package directories (default ".") are the ones whose _test.go files are
// scanned; subdirectories are not.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

var (
	idPattern   = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*-[0-9]+$`)
	testPattern = regexp.MustCompile(`^(Test|Fuzz|Example)([A-Z0-9_].*)?$`)
	header      = []string{"ID", "Section", "Level", "Requirement", "Tests"}
	levels      = map[string]bool{
		"MUST": true, "MUST NOT": true, "REQUIRED": true, "SHALL": true, "SHALL NOT": true,
		"SHOULD": true, "SHOULD NOT": true, "RECOMMENDED": true, "NOT RECOMMENDED": true,
		"MAY": true, "OPTIONAL": true, "Normative": true,
	}
)

// item is one checklist row.
type item struct {
	id    string
	line  int
	tests []string // empty when not applicable
	na    bool
}

// test is one test function and the items its doc comment names.
type test struct {
	name  string
	pos   string
	items []string
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("checklist", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "CHECKLIST.md", "the checklist to check")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dirs := fs.Args()
	if len(dirs) == 0 {
		dirs = []string{"."}
	}

	var problems []string
	report := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	items, err := parseChecklist(*file, report)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	tests, err := scanTests(dirs, report)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}

	na := 0
	for _, it := range items {
		if it.na {
			na++
			continue
		}
		for _, name := range it.tests {
			tc, ok := tests[name]
			switch {
			case !ok:
				report("%s:%d: %s lists %s, which is not a test", *file, it.line, it.id, name)
			case !slices.Contains(tc.items, it.id):
				report("%s: %s does not name %s, which lists it", tc.pos, name, it.id)
			}
		}
	}
	names := make([]string, 0, len(tests))
	for name := range tests {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		tc := tests[name]
		if len(tc.items) == 0 && !strings.HasPrefix(name, "Example") {
			report("%s: %s names no checklist item", tc.pos, name)
		}
		for _, id := range tc.items {
			it, ok := items[id]
			switch {
			case !ok:
				report("%s: %s names %s, which is not in %s", tc.pos, name, id, *file)
			case it.na:
				report("%s: %s names %s, which is not applicable", tc.pos, name, id)
			case !slices.Contains(it.tests, name):
				report("%s:%d: %s does not list %s, which names it", *file, it.line, id, name)
			}
		}
	}

	if len(problems) > 0 {
		for _, p := range problems {
			_, _ = fmt.Fprintln(stderr, p)
		}
		_, _ = fmt.Fprintf(stderr, "%s: %d problem(s)\n", *file, len(problems))
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s: %d items (%d mapped to tests, %d not applicable), %d tests\n",
		*file, len(items), len(items)-na, na, len(tests))
	return 0
}

// parseChecklist reads the checklist tables of file.
func parseChecklist(file string, report func(string, ...any)) (map[string]*item, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	items := map[string]*item{}
	inTable := false
	for n, line := range strings.Split(string(data), "\n") {
		n++
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			inTable = false
			continue
		}
		cells := splitRow(line)
		if slices.Equal(cells, header) {
			inTable = true
			continue
		}
		if !inTable || isSeparator(cells) {
			continue
		}
		if len(cells) != len(header) {
			report("%s:%d: row has %d cells, want %d", file, n, len(cells), len(header))
			continue
		}
		it := &item{id: cells[0], line: n}
		switch {
		case !idPattern.MatchString(it.id):
			report("%s:%d: %q is not an item ID like SPF-EVAL-04", file, n, it.id)
			continue
		case items[it.id] != nil:
			report("%s:%d: %s is already used on line %d", file, n, it.id, items[it.id].line)
			continue
		case cells[1] == "":
			report("%s:%d: %s has no RFC section", file, n, it.id)
		case !levels[cells[2]]:
			report("%s:%d: %s has level %q, want an RFC 2119 keyword or Normative", file, n, it.id, cells[2])
		case cells[3] == "":
			report("%s:%d: %s states no requirement", file, n, it.id)
		}
		items[it.id] = it
		if reason, ok := strings.CutPrefix(cells[4], "n/a:"); ok {
			it.na = true
			if strings.TrimSpace(reason) == "" {
				report("%s:%d: %s is not applicable but gives no reason", file, n, it.id)
			}
			continue
		}
		for _, name := range strings.Split(cells[4], ",") {
			name = strings.Trim(strings.TrimSpace(name), "`")
			if name == "" {
				continue
			}
			if !testPattern.MatchString(name) {
				report("%s:%d: %s lists %q, which is not a test function name", file, n, it.id, name)
				continue
			}
			it.tests = append(it.tests, name)
		}
		if len(it.tests) == 0 {
			report("%s:%d: %s names no test (write \"n/a: <reason>\" if it does not apply)", file, n, it.id)
		}
	}
	return items, nil
}

// scanTests collects the Test, Fuzz and Example functions of the _test.go
// files in dirs, with the items their doc comments name.
func scanTests(dirs []string, report func(string, ...any)) (map[string]*test, error) {
	tests := map[string]*test{}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if err != nil {
			return nil, err
		}
		for _, path := range files {
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil, err
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !testPattern.MatchString(fn.Name.Name) {
					continue
				}
				tc := &test{name: fn.Name.Name, pos: fset.Position(fn.Pos()).String()}
				if prev := tests[tc.name]; prev != nil {
					report("%s: %s is also defined at %s", tc.pos, tc.name, prev.pos)
					continue
				}
				tc.items = docItems(fn.Doc)
				tests[tc.name] = tc
			}
		}
	}
	return tests, nil
}

// docItems returns the item IDs named by "checklist:" lines of a doc comment.
func docItems(doc *ast.CommentGroup) []string {
	var ids []string
	for _, line := range strings.Split(doc.Text(), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "checklist:"); ok {
			ids = append(ids, strings.FieldsFunc(rest, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })...)
		}
	}
	return ids
}

// splitRow splits a Markdown table row into trimmed cells.
func splitRow(line string) []string {
	line = strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|")
	cells := strings.Split(line, "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

func isSeparator(cells []string) bool {
	for _, c := range cells {
		if strings.Trim(c, ":-") != "" {
			return false
		}
	}
	return true
}
