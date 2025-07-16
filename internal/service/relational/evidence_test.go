package relational

//
//import (
//	"github.com/compliance-framework/api/internal/converters/labelfilter"
//	"github.com/compliance-framework/api/internal/logging"
//	"github.com/stretchr/testify/assert"
//	"go.uber.org/zap"
//	"gorm.io/driver/postgres"
//	"gorm.io/gorm"
//	gormLogger "gorm.io/gorm/logger"
//	"testing"
//)
//
//func TestEvidenceSearchFilter(t *testing.T) {
//	logger, _ := zap.NewDevelopment()
//
//	db, err := gorm.Open(postgres.New(postgres.Config{}), &gorm.Config{
//		DisableForeignKeyConstraintWhenMigrating: true,
//		DisableAutomaticPing:                     true,
//		Logger:                                   logging.NewZapGormLogger(logger.Sugar(), gormLogger.Warn),
//	})
//	assert.NoError(t, err)
//
//	SearchEvidenceByFilter(db, labelfilter.Filter{})
//
//	// Simple =
//	SearchEvidenceByFilter(db, labelfilter.Filter{
//		Scope: &labelfilter.Scope{
//			Condition: &labelfilter.Condition{
//				Label:    "provider",
//				Operator: "=",
//				Value:    "aws",
//			},
//		},
//	})
//
//	// Simple !=
//	SearchEvidenceByFilter(db, labelfilter.Filter{
//		Scope: &labelfilter.Scope{
//			Condition: &labelfilter.Condition{
//				Label:    "provider",
//				Operator: "!=",
//				Value:    "aws",
//			},
//		},
//	})
//
//	// Simple = AND =
//	SearchEvidenceByFilter(db, labelfilter.Filter{
//		Scope: &labelfilter.Scope{
//			Query: &labelfilter.Query{
//				Operator: "AND",
//				Scopes: []labelfilter.Scope{
//					{
//						Condition: &labelfilter.Condition{
//							Label:    "provider",
//							Operator: "=",
//							Value:    "aws",
//						},
//					},
//					{
//						Condition: &labelfilter.Condition{
//							Label:    "service",
//							Operator: "=",
//							Value:    "ec2",
//						},
//					},
//				},
//			},
//		},
//	})
//
//	// Simple = OR =
//	SearchEvidenceByFilter(db, labelfilter.Filter{
//		Scope: &labelfilter.Scope{
//			Query: &labelfilter.Query{
//				Operator: "OR",
//				Scopes: []labelfilter.Scope{
//					{
//						Condition: &labelfilter.Condition{
//							Label:    "provider",
//							Operator: "=",
//							Value:    "aws",
//						},
//					},
//					{
//						Condition: &labelfilter.Condition{
//							Label:    "service",
//							Operator: "=",
//							Value:    "ec2",
//						},
//					},
//				},
//			},
//		},
//	})
//
//	// Sub Query = OR =
//	SearchEvidenceByFilter(db, labelfilter.Filter{
//		Scope: &labelfilter.Scope{
//			Query: &labelfilter.Query{
//				Operator: "AND",
//				Scopes: []labelfilter.Scope{
//					{
//						Condition: &labelfilter.Condition{
//							Label:    "provider",
//							Operator: "=",
//							Value:    "aws",
//						},
//					},
//					{
//						Query: &labelfilter.Query{
//							Operator: "OR",
//							Scopes: []labelfilter.Scope{
//								{
//									Condition: &labelfilter.Condition{
//										Label:    "instance",
//										Operator: "=",
//										Value:    "i-1",
//									},
//								},
//								{
//									Condition: &labelfilter.Condition{
//										Label:    "instance",
//										Operator: "=",
//										Value:    "i-2",
//									},
//								},
//							},
//						},
//					},
//				},
//			},
//		},
//	})
//}
