package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/osintfw/osint/pkg/types"
)

func Export(results []types.ModuleResult, format, filename string) error {
	switch strings.ToLower(format) {
	case "json":
		return exportJSON(results, filename)
	case "csv":
		return exportCSV(results, filename)
	case "markdown", "md":
		return exportMarkdown(results, filename)
	case "html":
		return exportHTML(results, filename)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func exportJSON(results []types.ModuleResult, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func exportCSV(results []types.ModuleResult, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"Module", "Target", "Timestamp", "Data"})
	for _, r := range results {
		data, _ := json.Marshal(r.Data)
		w.Write([]string{r.Module, r.Target, r.Timestamp.Format(time.RFC3339), string(data)})
	}
	w.Flush()
	return w.Error()
}

func exportMarkdown(results []types.ModuleResult, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# OSINT Report\n\nGenerated: %s\n\n", time.Now().Format(time.RFC3339))
	for _, r := range results {
		fmt.Fprintf(f, "## %s: %s\n\n", r.Module, r.Target)
		fmt.Fprintf(f, "- **Timestamp**: %s\n", r.Timestamp.Format(time.RFC3339))
		if r.Error != nil {
			fmt.Fprintf(f, "- **Error**: %s\n", r.Error)
		}
		data, _ := json.MarshalIndent(r.Data, "", "  ")
		fmt.Fprintf(f, "```json\n%s\n```\n\n", string(data))
	}
	return nil
}

func exportHTML(results []types.ModuleResult, filename string) error {
	const tpl = `<!DOCTYPE html>
<html>
<head><title>OSINT Report</title>
<style>
body{font-family:sans-serif;margin:40px;background:#f5f5f5;}
.container{max-width:1200px;margin:0 auto;background:#fff;padding:30px;box-shadow:0 0 10px rgba(0,0,0,0.1);}
h1{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px;}
table{border-collapse:collapse;width:100%;margin-top:20px;}
th,td{border:1px solid #ddd;padding:12px;text-align:left;}
th{background-color:#3498db;color:white;}
tr:nth-child(even){background-color:#f9f9f9;}
pre{background:#f4f4f4;padding:10px;border-radius:4px;overflow-x:auto;}
.timestamp{color:#7f8c8d;font-size:0.9em;}
</style>
</head>
<body>
<div class="container">
<h1>OSINT Report</h1>
<p class="timestamp">Generated: {{.Generated}}</p>
<table>
<tr><th>Module</th><th>Target</th><th>Timestamp</th><th>Data</th></tr>
{{range .Results}}
<tr>
<td>{{.Module}}</td>
<td>{{.Target}}</td>
<td class="timestamp">{{.Timestamp}}</td>
<td><pre>{{.DataJSON}}</pre></td>
</tr>
{{end}}
</table>
</div>
</body>
</html>`

	type row struct {
		types.ModuleResult
		DataJSON string
	}

	var rows []row
	for _, r := range results {
		dj, _ := json.MarshalIndent(r.Data, "", "  ")
		rows = append(rows, row{ModuleResult: r, DataJSON: string(dj)})
	}

	data := struct {
		Generated string
		Results   []row
	}{
		Generated: time.Now().Format(time.RFC3339),
		Results:   rows,
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	t := template.Must(template.New("report").Parse(tpl))
	return t.Execute(f, data)
}
