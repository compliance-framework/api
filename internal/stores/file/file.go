package file

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
)

type FileDriver struct {
	Path string
}

func (f *FileDriver) Update(_ context.Context, collection, id string, object interface{}) error {
	// TODO - Implement proper upsert. A method 'MergeFrom' on the BaseModel is needed
	dirPath := f.Path + "/" + collection
	filePath := dirPath + "/" + id + ".gob"
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

func (f *FileDriver) Create(_ context.Context, collection, id string, object interface{}) error {
	dirPath := f.Path + "/" + collection
	filePath := dirPath + "/" + id + ".gob"
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

func (f *FileDriver) CreateMany(_ context.Context, collection string, objects map[string]interface{}) error {
	dirPath := f.Path + "/" + collection
	for id, object := range objects {
		filePath := dirPath + "/" + id + ".gob"
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			return err
		}
		dataFile, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		dataEncoder := gob.NewEncoder(dataFile)
		err = dataEncoder.Encode(object)
		if err != nil {
			return fmt.Errorf("failed to write on file: %w", err)
		}
	}
	return nil
}

func (f *FileDriver) Delete(_ context.Context, collection, id string) error {
	dirPath := f.Path + "/" + collection
	filePath := dirPath + "/" + id + ".gob"
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}
	return os.Remove(filePath)
}
func (f *FileDriver) DeleteWhere(_ context.Context, collection string, object interface{}, conditions map[string]interface{}) error {
	dirPath := f.Path + "/" + collection
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}
	for _, file := range files {
		filePath := dirPath + "/" + file.Name()
		dataFile, err := os.Open(filePath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return storeschema.NotFoundErr{}
			}
			return fmt.Errorf("failed to open file: %w", err)
		}
		dataEncoder := gob.NewDecoder(dataFile)
		err = dataEncoder.Decode(object)
		if err != nil {
			return err
		}
		d, _ := json.Marshal(object)
		mapping := make(map[string]interface{})
		json.Unmarshal(d, &mapping)
		for k, v := range conditions {
			if mapping[k] == v {
				err := os.Remove(filePath)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (f *FileDriver) Get(_ context.Context, collection, id string, object interface{}) error {
	dirPath := f.Path + "/" + collection
	filePath := dirPath + "/" + id + ".gob"
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
