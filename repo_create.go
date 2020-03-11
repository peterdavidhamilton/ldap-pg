package main

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"golang.org/x/xerrors"
)

func (r *Repository) Insert(entry *AddEntry) (int64, error) {
	tx := r.db.MustBegin()

	newID, err := r.insertWithTx(tx, entry)
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	err = tx.Commit()
	if err != nil {
		return 0, err
	}

	return newID, nil
}

func (r *Repository) insertWithTx(tx *sqlx.Tx, entry *AddEntry) (int64, error) {
	if entry.IsDC() {
		newID, err := r.insertDCEntry(tx, entry)
		if err != nil {
			return 0, err
		}

		// Always insert tree for DC entry
		err = insertTree(tx, newID, "/", "")
		if err != nil {
			return 0, err
		}

		return newID, nil
	}

	parent, err := r.findParent(tx, entry.DN())
	if err != nil {
		return 0, err
	}
	// No system error but can't find the parent
	if parent == nil {
		// TODO
		// return 0, NewNoSuchObjectWithMatchedDN(entry.DN().DNNormStr())
		return 0, NewNoSuchObject()
	}
	// Promote the parent entry to tree entry if no parent tree yet
	if !parent.HasChildren() {
		pp, err := parent.ParentDN(r.server)
		if err != nil {
			return 0, err
		}
		err = insertTree(tx, parent.ID, pp.ParentPath(), pp.DNOrigStr())
		if err != nil {
			return 0, err
		}
	}

	// After inserted parent tree, insert the entry
	newID, _, err := r.insertEntry(tx, parent, entry)
	if err != nil {
		return 0, err
	}

	// If the entry holds members, insert them
	err = r.insertMember(tx, newID, entry)
	if err != nil {
		return 0, err
	}

	return newID, nil
}

// findParent find a the parent entry of specified DN.
// If no entry, it returns nil without error.
func (r *Repository) findParent(tx *sqlx.Tx, dn *DN) (*DBEntryRecord, error) {
	parent, err := r.findDBEntryRecord(tx, dn.ParentDN())
	if err != nil {
		return nil, err
	}
	// parent might nil (not found case)
	return parent, nil
}

type DBEntryRecord struct {
	ID              int64  `db:"id"`
	ParentID        int64  `db:"parent_id"`
	RDNOrig         string `db:"rdn_orig"`
	ParentDNOrig    string `db:"parent_dn_orig"`  // No real clumn in t he table
	HasSubordinates string `db:"hassubordinates"` // No real column in the table
}

func (d *DBEntryRecord) HasChildren() bool {
	return d.HasSubordinates == "TRUE"
}

func (d *DBEntryRecord) ParentDN(server *Server) (*DN, error) {
	parentDN, err := server.NormalizeDN(d.ParentDNOrig)
	if err != nil {
		return nil, xerrors.Errorf("Failed to normalize parent DN: %s, err: %w",
			d.ParentDNOrig, err)
	}
	return parentDN, nil
}

// findDBEntry find a record in ldap_entry and ldap_tree table by DN.
// If no entry, it returns nil without error.
func (r *Repository) findDBEntryRecord(tx *sqlx.Tx, dn *DN) (*DBEntryRecord, error) {
	if dn.IsDC() {
		return r.findDCDBEntryRecord(tx, dn)
	}
	parentDN := dn.ParentDN()
	grandParentPath := "/"
	parentRDNNorm := ""
	if parentDN != nil {
		grandParentPath = parentDN.ParentPath()
		parentRDNNorm = parentDN.RDNNormStr()
	}

	q := fmt.Sprintf(`
		SELECT 
			e.id,
			e.parent_id,
			e.rdn_orig,
			pe.rdn_orig || ',' || pt.parent_dn_orig AS parent_dn_orig,
			CASE
				WHEN e.id IS NULL
				THEN 'FALSE'
				ELSE 'TRUE'
			END AS hassubordinates
		FROM 
			ldap_entry e 
			INNER JOIN ldap_tree pt ON pt.id = e.parent_id
			INNER JOIN ldap_entry pe ON pt.id = pe.id
			LEFT JOIN ldap_tree t ON t.id = e.id
		WHERE 
			pt.parent_path = :grand_parent_path
			AND pe.rdn_norm = :parent_rdn_norm
			AND e.rdn_norm = :rdn_norm 
	`)

	stmt, err := tx.PrepareNamed(q)
	if err != nil {
		return nil, xerrors.Errorf("Failed to prepare to find DBEntryRecord. query: %s, err: %w", q, err)
	}

	var dbEntry DBEntryRecord
	err = stmt.Get(&dbEntry, map[string]interface{}{
		"grand_parent_path": grandParentPath,
		"parent_rdn_norm":   parentRDNNorm,
		"rdn_norm":          dn.RDNNormStr(),
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, xerrors.Errorf("Failed to find DBEntryRecord. query: %s, err: %w", q, err)
	}

	return &dbEntry, nil
}

// findDBEntry find a record in ldap_entry and ldap_tree table by DN.
// If no entry, it returns nil without error.
func (r *Repository) findDCDBEntryRecord(tx *sqlx.Tx, dn *DN) (*DBEntryRecord, error) {
	if !dn.IsDC() {
		return nil, xerrors.Errorf("Invalid args. DN should be DC's DN")
	}

	suffix := r.server.GetSuffix()
	dcdn, err := NormalizeDN(nil, suffix)
	if err != nil {
		return nil, xerrors.Errorf("Failed to normalize DN: %s, err: %w", suffix, err)
	}
	parentDNOrig := dcdn.ParentDN().DNOrigStr()

	q := fmt.Sprintf(`
		SELECT 
			e.id,
			%d AS parent_id,
			'%s' AS rdn_orig,
			'%s' AS parent_dn_orig,
			'TRUE' AS hassubordinates
		FROM 
			ldap_entry e 
		WHERE 
			e.parent_id = :parent_id
	`, ROOT_ID, dcdn.RDNOrigStr(), parentDNOrig)

	stmt, err := tx.PrepareNamed(q)
	if err != nil {
		return nil, xerrors.Errorf("Failed to prepare to find DBEntryRecord. query: %s, err: %w", q, err)
	}

	var dbEntry DBEntryRecord
	err = stmt.Get(&dbEntry, map[string]interface{}{
		"parent_id": ROOT_ID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, xerrors.Errorf("Failed to find DBEntryRecord. query: %s, err: %w", q, err)
	}

	return &dbEntry, nil
}

func (r *Repository) hasParent(tx *sqlx.Tx, dn *DN) (bool, error) {
	_, err := r.FindByDN(tx, dn.ParentDN(), &FindOption{Lock: true})
	if err != nil {
		if isNoResult(err) {
			return false, nil
		}
		return false, xerrors.Errorf("Failed to find parent by DN: %s, err: %w", dn.DNNormStr(), err)
	}

	return true, nil
}

func (r *Repository) insertEntry(tx *sqlx.Tx, parent *DBEntryRecord, entry *AddEntry) (int64, int64, error) {
	if entry.ParentDN().IsDC() {
		return r.insertUnderDCEntry(tx, entry)
	}

	dbEntry, err := mapper.AddEntryToDBEntry(entry)
	if err != nil {
		return 0, 0, err
	}

	q := fmt.Sprintf(`
		INSERT INTO ldap_entry (parent_id, rdn_norm, rdn_orig, uuid, created, updated, attrs_norm, attrs_orig)
		VALUES (:parent_id, :rdn_norm, :rdn_orig, :uuid, :created, :updated, :attrs_norm, :attrs_orig)
		RETURNING id, parent_id
	`)

	log.Printf("insert query: %s", q)

	stmt, err := tx.PrepareNamed(q)
	if err != nil {
		return 0, 0, xerrors.Errorf("Failed to prepare query. query: %s, err: %w", err)
	}

	params := make(map[string]interface{})
	params["parent_id"] = parent.ID
	params["rdn_norm"] = entry.RDNNorm()
	params["rdn_orig"] = entry.RDNOrig()
	params["uuid"] = dbEntry.EntryUUID
	params["created"] = dbEntry.Created
	params["updated"] = dbEntry.Updated
	params["attrs_norm"] = dbEntry.AttrsNorm
	params["attrs_orig"] = dbEntry.AttrsOrig

	rows, err := tx.NamedStmt(stmt).Queryx(params)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			// Duplicate error
			if pqErr.Code == "23505" {
				log.Printf("debug: Already exists. parentID: %d, rdn_norm: %s", parent.ID, entry.RDNNorm())
				return 0, 0, NewAlreadyExists()
			}
		}
		return 0, 0, xerrors.Errorf("Failed to insert entry record. entry: %v, err: %w", entry, err)
	}
	defer rows.Close()

	var id int64
	var parentID int64
	if rows.Next() {
		rows.Scan(&id, &parentID)
	} else {
		log.Printf("debug: Already exists. parentID: %d, rdn_norm: %s", parentID, entry.RDNNorm())
		return 0, 0, NewAlreadyExists()
	}

	return id, parentID, nil
}

func (r *Repository) insertDCEntry(tx *sqlx.Tx, entry *AddEntry) (int64, error) {
	dbEntry, err := mapper.AddEntryToDBEntry(entry)
	if err != nil {
		return 0, err
	}

	rows, err := tx.NamedStmt(insertDCStmt).Queryx(map[string]interface{}{
		"rdn_norm":   entry.RDNNorm(),
		"rdn_orig":   entry.RDNOrig(),
		"uuid":       dbEntry.EntryUUID,
		"created":    dbEntry.Created,
		"updated":    dbEntry.Updated,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
	})
	if err != nil {
		return 0, xerrors.Errorf("Failed to insert DC entry record. DC entry: %v, err: %w", entry, err)
	}
	defer rows.Close()

	var id int64
	if rows.Next() {
		err := rows.Scan(&id)
		if err != nil {
			return 0, xerrors.Errorf("Failed to scan returning id. err: %w", err)
		}
	} else {
		log.Printf("warn: Already exists. parentID: %d, rdn_norm: %s", ROOT_ID, entry.RDNNorm())
		return 0, NewAlreadyExists()
	}

	return id, nil
}

func (r *Repository) insertUnderDCEntry(tx *sqlx.Tx, entry *AddEntry) (int64, int64, error) {
	dbEntry, err := mapper.AddEntryToDBEntry(entry)
	if err != nil {
		return 0, 0, err
	}

	rows, err := tx.NamedStmt(insertUnderDCStmt).Queryx(map[string]interface{}{
		"rdn_norm":   entry.RDNNorm(),
		"rdn_orig":   entry.RDNOrig(),
		"uuid":       dbEntry.EntryUUID,
		"created":    dbEntry.Created,
		"updated":    dbEntry.Updated,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
	})
	if err != nil {
		return 0, 0, xerrors.Errorf("Failed to insert entry record. entry: %v, err: %w", entry, err)
	}
	defer rows.Close()

	var id int64
	var parentID int64
	if rows.Next() {
		err := rows.Scan(&id, &parentID)
		if err != nil {
			return 0, 0, xerrors.Errorf("Failed to scan returning id. err: %w", err)
		}
	} else {
		log.Printf("warn: Already exists. dn: %s", entry.DN().DNOrigStr())
		return 0, 0, NewAlreadyExists()
	}

	return id, parentID, nil
}

func insertTree(tx *sqlx.Tx, id int64, parentPath, parentDNOrig string) error {
	_, err := tx.NamedStmt(insertTreeStmt).Exec(map[string]interface{}{
		"id":             id,
		"parent_path":    parentPath,
		"parent_dn_orig": parentDNOrig,
	})
	if err != nil {
		return xerrors.Errorf("Failed to insert tree record. id: %d, parent_path: %s, parent_dn_orig: %s, err: %w",
			id, parentPath, parentDNOrig, err)
	}
	return nil
}

func (r *Repository) insertMember(tx *sqlx.Tx, subjectID int64, entry *AddEntry) error {
	members := entry.Member()
	if len(members) == 0 {
		log.Printf("The new entry doesn't have member attributes. DN: %s", entry.DN().DNOrigStr())
		return nil
	}

	// First, cache all parent IDs
	// TODO should optimize if ldap_tree tables is too big
	dc, err := getDCDNOrig(tx)
	if err != nil {
		return err
	}
	dnIDCache := map[string]int64{} // dn_orig => id cache map
	dnIDCache[dc.DNOrig] = dc.ID

	nodeNorms, err := collectNodeNormByParentID(tx, dc.ID)
	if err != nil {
		return err
	}

	for _, node := range nodeNorms {
		dnIDCache[node.DNNorm] = node.ID
	}

	max := 100
	gcount := len(members) / max
	remain := len(members) % max

	for i := 0; i < gcount; i++ {
		start := i * max
		m := members[start : start+max]
		r.insertSubMembers(tx, subjectID, entry.DN(), m, dnIDCache)
	}

	if remain > 0 {
		start := gcount * max
		m := members[start : start+remain]
		r.insertSubMembers(tx, subjectID, entry.DN(), m, dnIDCache)
	}

	return nil
}

func (r *Repository) insertSubMembers(tx *sqlx.Tx, subjectID int64, dn *DN, members []*MemberEntry, dnIDCache map[string]int64) error {
	// Resolve IDs from memberOfDNs
	dns := make([]string, len(members))
	where := make([]string, len(members))
	params := make(map[string]interface{}, len(members))

	memberTypeCache := map[string]string{}

	for i, m := range members {
		dns[i] = m.MemberOfDNNorm

		dn, err := r.server.NormalizeDN(m.MemberOfDNNorm)
		if err != nil {
			log.Printf("info: Invalid member DN sintax. DN: %s, %s DN: %s", dn.DNOrigStr(), m.AttrNameNorm, m.MemberOfDNNorm)
			return NewInvalidDNSyntax()
		}
		parent := dn.ParentDN()
		parentID, ok := dnIDCache[parent.DNNormStr()]
		if !ok {
			log.Printf("info: Not found member DN. DN: %s, %s DN: %s", dn.DNOrigStr(), m.AttrNameNorm, m.MemberOfDNNorm)
			return NewInvalidDNSyntax()
		}
		where[i] = fmt.Sprintf("(parent_id = :parent_id_%d AND rdn_norm = :rdn_norm_%d)", i, i)
		params[fmt.Sprintf("parent_id_%d", i)] = parentID
		params[fmt.Sprintf("rdn_norm_%d", i)] = dn.RDNNormStr()

		// cache
		memberTypeCache[fmt.Sprintf("%d_%s", parentID, dn.RDNNormStr())] = m.AttrNameNorm
	}

	log.Printf("debug: Fetch start")

	query := fmt.Sprintf("SELECT id, parent_id, rdn_norm FROM ldap_entry WHERE %s", strings.Join(where, " OR "))

	rows, err := tx.NamedQuery(query, params)
	if err != nil {
		return xerrors.Errorf("Failed to fetch member's id. err: %w", err)
	}

	defer rows.Close()

	values := make([]string, len(where))
	params = make(map[string]interface{}, len(where))
	count := 0

	for rows.Next() {
		var id int64
		var parentID int64
		var rdnNorm string
		err := rows.Scan(&id, &parentID, &rdnNorm)
		if err != nil {
			return xerrors.Errorf("Failed to scan member's id. err: %w", err)
		}
		memberType, ok := memberTypeCache[fmt.Sprintf("%d_%s", parentID, rdnNorm)]
		if !ok {
			return xerrors.Errorf("Failed to fetch member's id. err: %w", err)
		}
		k1 := "a_" + strconv.Itoa(count)
		k2 := "o_" + strconv.Itoa(count)
		values[count] = fmt.Sprintf("(%d, :%s, :%s)", subjectID, k1, k2)
		params[k1] = memberType
		params[k2] = id

		count++
	}
	log.Printf("debuginfo: Fetch end")

	// Not found the member DN
	if count != len(dns) {
		log.Printf("warn: Invalid member DN. member dn: %v, values: %v", dns, values)
		return NewInvalidDNSyntax()
	}

	// work around
	rows.Close()

	log.Printf("debug: Insert start")

	insert := fmt.Sprintf("INSERT INTO ldap_member VALUES %s", strings.Join(values, ", "))

	_, err = tx.NamedExec(insert, params)
	if err != nil {
		return xerrors.Errorf("Failed to bulk insert members. err: %w", err)
	}

	log.Printf("debug: Insert end")

	return nil
}

type nordNorm struct {
	ID     int64  `db:"id"`
	DNNorm string `db:"dn_norm"`
}

func collectNodeNormByParentID(tx *sqlx.Tx, parentID int64) ([]*nordNorm, error) {
	if parentID == ROOT_ID {
		return nil, xerrors.Errorf("Invalid parentID: %d", parentID)
	}

	var rows *sqlx.Rows
	var err error
	if tx != nil {
		rows, err = tx.NamedStmt(collectNodeNormByParentIDStmt).Queryx(map[string]interface{}{
			"parent_id": parentID,
		})
	} else {
		rows, err = collectNodeNormByParentIDStmt.Queryx(map[string]interface{}{
			"parent_id": parentID,
		})
	}
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch child ID by parentID: %s, err: %w", parentID, err)
	}
	defer rows.Close()

	list := []*nordNorm{}
	for rows.Next() {
		child := nordNorm{}
		rows.StructScan(&child)
		list = append(list, &child)
	}

	err = rows.Err()
	if err != nil {
		log.Printf("error: Search children error: %#v", err)
		return nil, err
	}

	return list, nil
}
