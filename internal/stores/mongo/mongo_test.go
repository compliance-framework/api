package mongo

import (
	"context"
	"fmt"
	"testing"

	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	mockeryMocks "github.com/sv-tools/mongoifc/mocks/mockery"
	"go.mongodb.org/mongo-driver/mongo"
)

var ()

type Foo struct {
}

// TODO Refactor to use table tests
func TestGetFailErr(t *testing.T) {
	ctx := context.Background()
	cur := &mockeryMocks.SingleResult{}
	defer cur.AssertExpectations(t)
	cur.On("Err", mock.Anything).Return(fmt.Errorf("boom"))
	col := &mockeryMocks.Collection{}
	defer col.AssertExpectations(t)
	col.On("FindOne", ctx, mock.Anything).Return(cur, nil)
	db := &mockeryMocks.Database{}
	defer db.AssertExpectations(t)
	db.On("Collection", "foo").Return(col)
	cl := &mockeryMocks.Client{}
	cl.On("Database", mock.Anything).Return(db)
	cl.On("Disconnect", mock.Anything).Return(nil)
	p := &MongoDriver{client: cl, Url: "mongodb://127.0.0.1:27017", Database: "cf"}
	err := p.Get(context.TODO(), "foo", "one", &Foo{})
	assert.NotNil(t, err)
}

func TestGetSuccess(t *testing.T) {
	ctx := context.Background()
	cur := &mockeryMocks.SingleResult{}
	defer cur.AssertExpectations(t)
	cur.On("Err", mock.Anything).Return(nil)
	cur.On("Decode", mock.Anything).Return(nil)
	col := &mockeryMocks.Collection{}
	defer col.AssertExpectations(t)
	col.On("FindOne", ctx, mock.Anything).Return(cur, nil)
	db := &mockeryMocks.Database{}
	defer db.AssertExpectations(t)
	db.On("Collection", "foo").Return(col)
	cl := &mockeryMocks.Client{}
	cl.On("Database", mock.Anything).Return(db)
	cl.On("Disconnect", mock.Anything).Return(nil)
	p := &MongoDriver{client: cl, Url: "mongodb://127.0.0.1:27017", Database: "cf"}
	err := p.Get(context.TODO(), "foo", "one", &Foo{})
	assert.Nil(t, err)
}

func TestGetFailDecode(t *testing.T) {
	ctx := context.Background()
	cur := &mockeryMocks.SingleResult{}
	defer cur.AssertExpectations(t)
	cur.On("Err", mock.Anything).Return(nil)
	cur.On("Decode", mock.Anything).Return(fmt.Errorf("Fail decode"))
	col := &mockeryMocks.Collection{}
	defer col.AssertExpectations(t)
	col.On("FindOne", ctx, mock.Anything).Return(cur, nil)
	db := &mockeryMocks.Database{}
	defer db.AssertExpectations(t)
	db.On("Collection", "foo").Return(col)
	cl := &mockeryMocks.Client{}
	cl.On("Database", mock.Anything).Return(db)
	cl.On("Disconnect", mock.Anything).Return(nil)
	p := &MongoDriver{client: cl, Url: "mongodb://127.0.0.1:27017", Database: "cf"}
	err := p.Get(context.TODO(), "foo", "one", &Foo{})
	assert.NotNil(t, err)
}

func TestGetFailNoDocument(t *testing.T) {
	ctx := context.Background()
	cur := &mockeryMocks.SingleResult{}
	defer cur.AssertExpectations(t)
	cur.On("Err", mock.Anything).Return(mongo.ErrNoDocuments)
	col := &mockeryMocks.Collection{}
	defer col.AssertExpectations(t)
	col.On("FindOne", ctx, mock.Anything).Return(cur, nil)
	db := &mockeryMocks.Database{}
	defer db.AssertExpectations(t)
	db.On("Collection", "foo").Return(col)
	cl := &mockeryMocks.Client{}
	cl.On("Database", mock.Anything).Return(db)
	cl.On("Disconnect", mock.Anything).Return(nil)
	p := &MongoDriver{client: cl, Url: "mongodb://127.0.0.1:27017", Database: "cf"}
	err := p.Get(context.TODO(), "foo", "one", &Foo{})
	require.NotNil(t, err)
	assert.ErrorIs(t, err, storeschema.NotFoundErr{})
}

type colInputs struct {
	name    string
	inputs  []interface{}
	outputs []interface{}
	run     func(args mock.Arguments)
}
type TestCase struct {
	name             string
	cursorInputs     map[string]colInputs
	collectionInputs map[string]colInputs
	expectedErr      string
}

func TestUpdate(t *testing.T) {
	tc := []TestCase{
		{
			name: "success",
			collectionInputs: map[string]colInputs{
				"ReplaceOne": {
					inputs:  []interface{}{mock.Anything, mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.UpdateResult{ModifiedCount: 1, MatchedCount: 1}, nil},
				},
			},
		},
		{
			name: "Not Found",
			collectionInputs: map[string]colInputs{
				"ReplaceOne": {
					inputs:  []interface{}{mock.Anything, mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.UpdateResult{ModifiedCount: 1, MatchedCount: 0}, nil},
				},
			},
			expectedErr: "object not found",
		},
		{
			name: "not modified",
			collectionInputs: map[string]colInputs{
				"ReplaceOne": {
					inputs:  []interface{}{mock.Anything, mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.UpdateResult{ModifiedCount: 0, MatchedCount: 1}, nil},
				},
			},
			expectedErr: "could not modify document one",
		},
		{
			name: "error on call",
			collectionInputs: map[string]colInputs{
				"ReplaceOne": {
					inputs:  []interface{}{mock.Anything, mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.UpdateResult{ModifiedCount: 0, MatchedCount: 0}, fmt.Errorf("boom!")},
				},
			},
			expectedErr: "could not update object",
		},
	}
	for i, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			col := &mockeryMocks.Collection{}
			defer col.AssertExpectations(t)
			for k, v := range tc[i].collectionInputs {
				col.On(k, v.inputs...).Return(v.outputs...)
			}
			db := &mockeryMocks.Database{}
			defer db.AssertExpectations(t)
			db.On("Collection", "foo").Return(col)
			cl := &mockeryMocks.Client{}
			cl.On("Database", mock.Anything).Return(db)
			cl.On("Disconnect", mock.Anything).Return(nil)
			p := &MongoDriver{client: cl, Url: "mongodb://127.0.0.1:27017", Database: "cf"}
			err := p.Update(context.TODO(), "foo", "one", &Foo{})
			if tc[i].expectedErr != "" {
				require.NotNil(t, err)
				assert.ErrorContains(t, err, tc[i].expectedErr)
			} else {
				require.Nil(t, err)
			}

		})
	}
}

func TestCreate(t *testing.T) {
	tc := []TestCase{
		{
			name: "success",
			collectionInputs: map[string]colInputs{
				"InsertOne": {
					inputs:  []interface{}{mock.Anything, mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.InsertOneResult{}, nil},
				},
			},
		},
		{
			name: "error on call",
			collectionInputs: map[string]colInputs{
				"InsertOne": {
					inputs:  []interface{}{mock.Anything, mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.InsertOneResult{}, fmt.Errorf("boom!")},
				},
			},
			expectedErr: "could not create object",
		},
	}
	for i, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			col := &mockeryMocks.Collection{}
			defer col.AssertExpectations(t)
			for k, v := range tc[i].collectionInputs {
				col.On(k, v.inputs...).Return(v.outputs...)
			}
			db := &mockeryMocks.Database{}
			defer db.AssertExpectations(t)
			db.On("Collection", "foo").Return(col)
			cl := &mockeryMocks.Client{}
			cl.On("Database", mock.Anything).Return(db)
			cl.On("Disconnect", mock.Anything).Return(nil)
			p := &MongoDriver{client: cl, Url: "mongodb://127.0.0.1:27017", Database: "cf"}
			err := p.Create(context.TODO(), "foo", "one", &Foo{})
			if tc[i].expectedErr != "" {
				require.NotNil(t, err)
				assert.ErrorContains(t, err, tc[i].expectedErr)
			} else {
				require.Nil(t, err)
			}

		})
	}
}

func TestCreateMany(t *testing.T) {
	tc := []TestCase{
		{
			name: "success",
			collectionInputs: map[string]colInputs{
				"InsertMany": {
					inputs:  []interface{}{mock.Anything, mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.InsertManyResult{}, nil},
				},
			},
		},
		{
			name: "error on call",
			collectionInputs: map[string]colInputs{
				"InsertMany": {
					inputs:  []interface{}{mock.Anything, mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.InsertManyResult{}, fmt.Errorf("boom!")},
				},
			},
			expectedErr: "could not create object",
		},
	}
	for i, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			col := &mockeryMocks.Collection{}
			defer col.AssertExpectations(t)
			for k, v := range tc[i].collectionInputs {
				col.On(k, v.inputs...).Return(v.outputs...)
			}
			db := &mockeryMocks.Database{}
			defer db.AssertExpectations(t)
			db.On("Collection", "foo").Return(col)
			cl := &mockeryMocks.Client{}
			cl.On("Database", mock.Anything).Return(db)
			cl.On("Disconnect", mock.Anything).Return(nil)
			p := &MongoDriver{client: cl, Url: "mongodb://127.0.0.1:27017", Database: "cf"}
			err := p.CreateMany(context.TODO(), "foo", map[string]interface{}{"one": &Foo{}, "two": &Foo{}})
			if tc[i].expectedErr != "" {
				require.NotNil(t, err)
				assert.ErrorContains(t, err, tc[i].expectedErr)
			} else {
				require.Nil(t, err)
			}

		})
	}
}

func TestDeletewhere(t *testing.T) {
	tc := []TestCase{
		{
			name: "success",
			collectionInputs: map[string]colInputs{
				"DeleteMany": {
					inputs:  []interface{}{mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.DeleteResult{}, nil},
				},
			},
		},
		{
			name: "error on call",
			collectionInputs: map[string]colInputs{
				"DeleteMany": {
					inputs:  []interface{}{mock.Anything, mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.DeleteResult{}, fmt.Errorf("boom!")},
				},
			},
			expectedErr: "could not delete object",
		},
	}
	for i, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			col := &mockeryMocks.Collection{}
			defer col.AssertExpectations(t)
			for k, v := range tc[i].collectionInputs {
				col.On(k, v.inputs...).Return(v.outputs...)
			}
			db := &mockeryMocks.Database{}
			defer db.AssertExpectations(t)
			db.On("Collection", "foo").Return(col)
			cl := &mockeryMocks.Client{}
			cl.On("Database", mock.Anything).Return(db)
			cl.On("Disconnect", mock.Anything).Return(nil)
			p := &MongoDriver{client: cl, Url: "mongodb://127.0.0.1:27017", Database: "cf"}
			err := p.DeleteWhere(context.TODO(), "foo", &Foo{}, map[string]interface{}{"one-two": "three-four"})
			if tc[i].expectedErr != "" {
				require.NotNil(t, err)
				assert.ErrorContains(t, err, tc[i].expectedErr)
			} else {
				require.Nil(t, err)
			}

		})
	}
}

func TestDelete(t *testing.T) {
	tc := []TestCase{
		{
			name: "success",
			collectionInputs: map[string]colInputs{
				"DeleteOne": {
					inputs:  []interface{}{mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.DeleteResult{DeletedCount: 1}, nil},
				},
			},
		},
		{
			name: "not found",
			collectionInputs: map[string]colInputs{
				"DeleteOne": {
					inputs:  []interface{}{mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.DeleteResult{DeletedCount: 0}, nil},
				},
			},
			expectedErr: "object not found",
		},
		{
			name: "error on call",
			collectionInputs: map[string]colInputs{
				"DeleteOne": {
					inputs:  []interface{}{mock.Anything, mock.Anything, mock.Anything},
					outputs: []interface{}{&mongo.DeleteResult{}, fmt.Errorf("boom!")},
				},
			},
			expectedErr: "could not delete object",
		},
	}
	for i, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			col := &mockeryMocks.Collection{}
			defer col.AssertExpectations(t)
			for k, v := range tc[i].collectionInputs {
				if v.run != nil {
					col.On(k, v.inputs...).Run(v.run).Return(v.outputs...)
				} else {
					col.On(k, v.inputs...).Return(v.outputs...)
				}
			}
			db := &mockeryMocks.Database{}
			defer db.AssertExpectations(t)
			db.On("Collection", "foo").Return(col)
			cl := &mockeryMocks.Client{}
			cl.On("Database", mock.Anything).Return(db)
			cl.On("Disconnect", mock.Anything).Return(nil)
			p := &MongoDriver{client: cl, Url: "mongodb://127.0.0.1:27017", Database: "cf"}
			err := p.Delete(context.TODO(), "foo", "one")
			if tc[i].expectedErr != "" {
				require.NotNil(t, err)
				assert.ErrorContains(t, err, tc[i].expectedErr)
			} else {
				require.Nil(t, err)
			}

		})
	}
}

func TestGetAll(t *testing.T) {
	tc := []TestCase{
		{
			name: "success",
			cursorInputs: map[string]colInputs{
				"Close": {
					inputs:  []interface{}{mock.Anything},
					outputs: []interface{}{nil},
				},
				"Next": {
					inputs:  []interface{}{mock.Anything},
					outputs: []interface{}{false},
				},
				// TODO - Not sure how to test cursor.Next() with mongoifc
				// "Decode": {
				// 	inputs:  []interface{}{mock.Anything},
				// 	outputs: []interface{}{nil},
				// },
			},
			collectionInputs: map[string]colInputs{
				"Find": {
					name:    "cursor",
					outputs: []interface{}{nil},
				},
			},
		},
	}
	for i, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			cur := &mockeryMocks.Cursor{}
			for k, v := range tc[i].cursorInputs {
				cur.On(k, v.inputs...).Return(v.outputs...)
			}
			defer cur.AssertExpectations(t)
			col := &mockeryMocks.Collection{}
			for k, v := range tc[i].collectionInputs {
				if v.name != "" {
					if v.name == "cursor" {
						out := make([]interface{}, 0)
						out = append(out, cur)
						out = append(out, v.outputs...)
						col.On("Find", mock.Anything, mock.Anything).Return(out...)
					} else {
						col.On(v.name, v.inputs...).Return(v.outputs...)
					}
				} else {
					col.On(k, v.inputs...).Return(v.outputs...)
				}
			}
			db := &mockeryMocks.Database{}
			defer db.AssertExpectations(t)
			db.On("Collection", "foo").Return(col)
			cl := &mockeryMocks.Client{}
			cl.On("Database", mock.Anything).Return(db)
			cl.On("Disconnect", mock.Anything).Return(nil)
			p := &MongoDriver{client: cl, Url: "mongodb://127.0.0.1:27017", Database: "cf"}
			res, err := p.GetAll(context.TODO(), "foo", &Foo{}, map[string]interface{}{"test-filter": "foo-bar"})
			assert.NotNil(t, res)
			if tc[i].expectedErr != "" {
				require.NotNil(t, err)
				assert.ErrorContains(t, err, tc[i].expectedErr)
			} else {
				require.Nil(t, err)
			}
		})
	}
}
