package risks

import (
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm/clause"
)

// OnPoamItemCompleted is called by the POAM handler when a POAM item
// transitions to the "completed" status. It advances every linked risk that is
// currently in mitigating-planned status to mitigating-implemented only when
// all POAM items linked to that risk are completed, emitting a status_changed
// event and a poam_completed event for each transitioned risk.
//
// Only risks in mitigating-planned are advanced; risks in any other status are
// left untouched (they may have been manually moved or re-accepted). If any
// linked POAM item for a risk remains non-completed, that risk is also left
// untouched.
func (s *RiskService) OnPoamItemCompleted(poamItemID uuid.UUID, actorUserID *uuid.UUID) error {
	// Find all risk IDs linked to this POAM item.
	type linkRow struct {
		RiskID uuid.UUID
	}
	var links []linkRow
	if err := s.db.Raw(`
		SELECT risk_id FROM ccf_poam_item_risk_links WHERE poam_item_id = ?
	`, poamItemID).Scan(&links).Error; err != nil {
		return err
	}
	if len(links) == 0 {
		return nil
	}

	for _, link := range links {
		if err := s.advanceRiskToMitigatingImplemented(link.RiskID, poamItemID, actorUserID); err != nil {
			return err
		}
	}
	return nil
}

// advanceRiskToMitigatingImplemented transitions a single risk from
// mitigating-planned → mitigating-implemented inside its own transaction.
// If the risk is not in mitigating-planned, or if any linked POAM item remains
// non-completed, it is silently skipped.
func (s *RiskService) advanceRiskToMitigatingImplemented(riskID, poamItemID uuid.UUID, actorUserID *uuid.UUID) error {
	tx, err := beginTx(s.db)
	if err != nil {
		return err
	}
	defer rollbackTxOnPanic(tx)

	var risk Risk
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&risk, "id = ?", riskID).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Only advance risks that are in mitigating-planned.
	if risk.Status != string(RiskStatusMitigatingPlanned) {
		tx.Rollback()
		return nil
	}

	var activeLinkedPoamCount int64
	if err := tx.Raw(`
		SELECT COUNT(*)
		FROM ccf_poam_item_risk_links l
		JOIN ccf_poam_items p ON p.id = l.poam_item_id
		WHERE l.risk_id = ? AND p.status <> ?
	`, riskID, "completed").Scan(&activeLinkedPoamCount).Error; err != nil {
		tx.Rollback()
		return err
	}
	if activeLinkedPoamCount > 0 {
		tx.Rollback()
		return nil
	}

	oldStatus := risk.Status
	risk.Status = string(RiskStatusMitigatingImplemented)
	if err := tx.Save(&risk).Error; err != nil {
		tx.Rollback()
		return err
	}

	riskSnapshot, err := s.getRiskSnapshot(tx, riskID)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Emit status_changed event.
	if err := s.logRiskEventWithSnapshot(tx, riskID, RiskEventTypeStatusChange, actorUserID, datatypes.JSONMap{
		"from": oldStatus,
		"to":   risk.Status,
	}, riskSnapshot); err != nil {
		tx.Rollback()
		return err
	}

	// Emit poam_completed event.
	if err := s.logRiskEventWithSnapshot(tx, riskID, RiskEventTypePoamCompleted, actorUserID, datatypes.JSONMap{
		"poamItemId": poamItemID.String(),
	}, riskSnapshot); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}
