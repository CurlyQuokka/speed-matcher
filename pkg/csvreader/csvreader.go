package csvreader

import (
	"encoding/csv"
	"fmt"
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
