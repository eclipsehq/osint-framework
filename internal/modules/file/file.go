package file

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/osintfw/osint/pkg/types"
)

func Analyze(path string) types.ModuleResult {
	res := types.ModuleResult{
		Module:    "file",
		Target:    path,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	f, err := os.Open(path)
	if err != nil {
		res.Error = err
		return res
	}
	defer f.Close()

	// Hashes
	h256 := sha256.New()
	h1 := sha1.New()
	hmd5 := md5.New()

	f.Seek(0, io.SeekStart)
	mw := io.MultiWriter(h256, h1, hmd5)
	if _, err := io.Copy(mw, f); err != nil {
		res.Error = err
		return res
	}

	res.Data["sha256"] = fmt.Sprintf("%x", h256.Sum(nil))
	res.Data["sha1"] = fmt.Sprintf("%x", h1.Sum(nil))
	res.Data["md5"] = fmt.Sprintf("%x", hmd5.Sum(nil))

	// MIME
	f.Seek(0, io.SeekStart)
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	mimeType := http.DetectContentType(buf[:n])
	res.Data["mime"] = mimeType

	// Extension-based MIME
	ext := filepath.Ext(path)
	if ext != "" {
		res.Data["extension"] = ext
		res.Data["ext_mime"] = mime.TypeByExtension(ext)
	}

	// Entropy
	f.Seek(0, io.SeekStart)
	entropy, _ := calculateEntropy(f)
	res.Data["entropy"] = fmt.Sprintf("%.4f", entropy)

	// Image detection (basic)
	if ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".tiff" || ext == ".gif" || ext == ".bmp" || ext == ".webp" {
		res.Data["image"] = true
		res.Data["exif_note"] = "EXIF extraction requires an external library; install github.com/rwcarlsen/goexif or github.com/dsoprea/go-exif for full metadata support"
	}

	// PDF check
	if ext == ".pdf" {
		f.Seek(0, io.SeekStart)
		header := make([]byte, 5)
		f.Read(header)
		if string(header) == "%PDF-" {
			res.Data["pdf_header"] = string(header)
			res.Data["is_pdf"] = true
		}
	}

	// Office doc check
	if ext == ".docx" || ext == ".xlsx" || ext == ".pptx" {
		res.Data["office_open_xml"] = true
	}

	return res
}

func calculateEntropy(r io.Reader) (float64, error) {
	const bufferSize = 1024 * 1024
	buf := make([]byte, bufferSize)
	var freq [256]int
	total := 0

	for {
		n, err := r.Read(buf)
		if n > 0 {
			for i := 0; i < n; i++ {
				freq[buf[i]]++
				total++
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}

	if total == 0 {
		return 0, nil
	}

	var entropy float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy, nil
}
