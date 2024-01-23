package csvreader

import (
	"encoding/csv"
	"fmt"
	"mime/multipart"
	"os"
)

type CSVReader struct {
	Data [][]string
}

func (cr *CSVReader) LoadData(path string) error {

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", path, err)
	}

	defer f.Close()

	// read csv values using csv.Reader
	reader := csv.NewReader(f)
	cr.Data, err = reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}

	return nil
}

func (cr *CSVReader) LoadDataFromFile(file multipart.File, filename string) error {
	// read csv values using csv.Reader
	reader := csv.NewReader(file)
	var err error
	cr.Data, err = reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	return nil
}
