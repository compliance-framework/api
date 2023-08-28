package file

import (
	"encoding/gob"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
)

type FileDriver struct {
	Path string
}

func (f *FileDriver) Update(id string, object schema.BaseModel) error {
	// TODO - Implement proper upsert. A method 'MergeFrom' on the BaseModel is needed
	dirPath := f.Path + strings.Join(strings.Split(id, "/")[:2], "/")
	filePath := f.Path + id + ".gob"
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}
	dataFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	dataEncoder := gob.NewEncoder(dataFile)
	return dataEncoder.Encode(object)
}

func (f *FileDriver) Create(id string, object schema.BaseModel) error {
	dirPath := f.Path + strings.Join(strings.Split(id, "/")[:2], "/")
	filePath := f.Path + id + ".gob"
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}
	dataFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	dataEncoder := gob.NewEncoder(dataFile)
	return dataEncoder.Encode(object)
}

func (f *FileDriver) Delete(id string) error {
	dirPath := f.Path + strings.Join(strings.Split(id, "/")[:2], "/")
	filePath := f.Path + id + ".gob"
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}
	return os.Remove(filePath)
}

func (f *FileDriver) Get(id string, object schema.BaseModel) error {
	dirPath := f.Path + strings.Join(strings.Split(id, "/")[:2], "/")
	filePath := f.Path + id + ".gob"
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}
	dataFile, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return storeschema.NotFoundErr{}
		}
		return fmt.Errorf("failed to open file: %w", err)
	}
	dataDecoder := gob.NewDecoder(dataFile)
	err = dataDecoder.Decode(object)
	return err
}

func init() {
	gob.Register([]interface{}{})
	gob.Register(map[string]interface{}{})
	storeschema.MustRegister("file", &FileDriver{})
}
