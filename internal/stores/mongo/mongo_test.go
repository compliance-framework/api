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
