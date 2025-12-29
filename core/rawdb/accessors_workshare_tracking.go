// Workshare tracking experiment database accessors

package rawdb

import (
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/ethdb"
	"google.golang.org/protobuf/proto"
)

// WriteWorkshareReception stores a workshare reception record
func WriteWorkshareReception(db ethdb.KeyValueWriter, reception *types.WorkshareReception) error {
	if reception == nil {
		return nil
	}
	protoReception := reception.ProtoEncode()
	data, err := proto.Marshal(protoReception)
	if err != nil {
		return err
	}
	return db.Put(workshareReceptionKey(reception.WorkshareHash), data)
}

// ReadWorkshareReception retrieves a workshare reception record
func ReadWorkshareReception(db ethdb.Reader, hash common.Hash) (*types.WorkshareReception, error) {
	data, _ := db.Get(workshareReceptionKey(hash))
	if len(data) == 0 {
		return nil, nil
	}
	protoReception := new(types.ProtoWorkshareReception)
	if err := proto.Unmarshal(data, protoReception); err != nil {
		return nil, err
	}
	reception := new(types.WorkshareReception)
	if err := reception.ProtoDecode(protoReception, db.Location()); err != nil {
		return nil, err
	}
	return reception, nil
}

// DeleteWorkshareReception removes a workshare reception record
func DeleteWorkshareReception(db ethdb.KeyValueWriter, hash common.Hash) {
	db.Delete(workshareReceptionKey(hash))
}

// WriteWorkerInclusion records when worker adds workshare to pending block
func WriteWorkerInclusion(db ethdb.KeyValueWriter, record *types.WorkerInclusionRecord) error {
	if record == nil {
		return nil
	}
	protoRecord := record.ProtoEncode()
	data, err := proto.Marshal(protoRecord)
	if err != nil {
		return err
	}
	return db.Put(workerInclusionKey(record.WorkshareHash), data)
}

// ReadWorkerInclusion retrieves a worker inclusion record
func ReadWorkerInclusion(db ethdb.Reader, hash common.Hash) (*types.WorkerInclusionRecord, error) {
	data, _ := db.Get(workerInclusionKey(hash))
	if len(data) == 0 {
		return nil, nil
	}
	protoRecord := new(types.ProtoWorkerInclusionRecord)
	if err := proto.Unmarshal(data, protoRecord); err != nil {
		return nil, err
	}
	record := new(types.WorkerInclusionRecord)
	if err := record.ProtoDecode(protoRecord); err != nil {
		return nil, err
	}
	return record, nil
}

// DeleteWorkerInclusion removes a worker inclusion record
func DeleteWorkerInclusion(db ethdb.KeyValueWriter, hash common.Hash) {
	db.Delete(workerInclusionKey(hash))
}

// WriteMissedWorkshare records a workshare that expired without inclusion
func WriteMissedWorkshare(db ethdb.KeyValueWriter, missed *types.MissedWorkshare) error {
	if missed == nil {
		return nil
	}
	protoMissed := missed.ProtoEncode()
	data, err := proto.Marshal(protoMissed)
	if err != nil {
		return err
	}
	return db.Put(missedWorkshareKey(missed.WorkshareHash), data)
}

// ReadMissedWorkshare retrieves a missed workshare record
func ReadMissedWorkshare(db ethdb.Reader, hash common.Hash) (*types.MissedWorkshare, error) {
	data, _ := db.Get(missedWorkshareKey(hash))
	if len(data) == 0 {
		return nil, nil
	}
	protoMissed := new(types.ProtoMissedWorkshare)
	if err := proto.Unmarshal(data, protoMissed); err != nil {
		return nil, err
	}
	missed := new(types.MissedWorkshare)
	if err := missed.ProtoDecode(protoMissed, db.Location()); err != nil {
		return nil, err
	}
	return missed, nil
}

// DeleteMissedWorkshare removes a missed workshare record
func DeleteMissedWorkshare(db ethdb.KeyValueWriter, hash common.Hash) {
	db.Delete(missedWorkshareKey(hash))
}

// WriteReorgEvent records a chain reorganization event
func WriteReorgEvent(db ethdb.KeyValueWriter, event *types.ReorgEvent) error {
	if event == nil {
		return nil
	}
	protoEvent := event.ProtoEncode()
	data, err := proto.Marshal(protoEvent)
	if err != nil {
		return err
	}
	return db.Put(reorgEventKey(event.Timestamp), data)
}

// ReadReorgEvent retrieves a reorg event by timestamp
func ReadReorgEvent(db ethdb.Reader, timestamp uint64) (*types.ReorgEvent, error) {
	data, _ := db.Get(reorgEventKey(timestamp))
	if len(data) == 0 {
		return nil, nil
	}
	protoEvent := new(types.ProtoReorgEvent)
	if err := proto.Unmarshal(data, protoEvent); err != nil {
		return nil, err
	}
	event := new(types.ReorgEvent)
	if err := event.ProtoDecode(protoEvent); err != nil {
		return nil, err
	}
	return event, nil
}

// AddWorkshareToBlockIndex adds a workshare hash to the block's workshare index
// This allows us to find all workshares received for a specific block height
func AddWorkshareToBlockIndex(db ethdb.KeyValueWriter, readDb ethdb.Reader, blockNumber uint64, workshareHash common.Hash) error {
	key := workshareByBlockKey(blockNumber)
	data, _ := readDb.Get(key)

	protoHashes := new(common.ProtoHashes)
	if len(data) > 0 {
		if err := proto.Unmarshal(data, protoHashes); err != nil {
			return err
		}
	}

	// Add new hash
	protoHashes.Hashes = append(protoHashes.Hashes, workshareHash.ProtoEncode())

	newData, err := proto.Marshal(protoHashes)
	if err != nil {
		return err
	}
	return db.Put(key, newData)
}

// GetWorksharesForBlock retrieves all workshare hashes received for a specific block height
func GetWorksharesForBlock(db ethdb.Reader, blockNumber uint64) ([]common.Hash, error) {
	data, _ := db.Get(workshareByBlockKey(blockNumber))
	if len(data) == 0 {
		return nil, nil
	}

	protoHashes := new(common.ProtoHashes)
	if err := proto.Unmarshal(data, protoHashes); err != nil {
		return nil, err
	}

	hashes := make([]common.Hash, len(protoHashes.Hashes))
	for i, ph := range protoHashes.Hashes {
		hashes[i].ProtoDecode(ph)
	}
	return hashes, nil
}

// DeleteWorksharesForBlock removes the workshare index for a block
func DeleteWorksharesForBlock(db ethdb.KeyValueWriter, blockNumber uint64) {
	db.Delete(workshareByBlockKey(blockNumber))
}

// CleanupOldWorkshareTrackingData removes tracking data older than specified block
func CleanupOldWorkshareTrackingData(db ethdb.KeyValueWriter, readDb ethdb.Reader, currentBlock, retentionBlocks uint64) error {
	if currentBlock <= retentionBlocks {
		return nil
	}

	cutoffBlock := currentBlock - retentionBlocks

	// Clean up 10 blocks at a time to avoid long pauses
	startBlock := cutoffBlock
	if cutoffBlock > 10 {
		startBlock = cutoffBlock - 10
	}

	for blockNum := startBlock; blockNum <= cutoffBlock; blockNum++ {
		hashes, err := GetWorksharesForBlock(readDb, blockNum)
		if err != nil {
			continue
		}
		for _, hash := range hashes {
			DeleteWorkshareReception(db, hash)
			DeleteWorkerInclusion(db, hash)
			DeleteMissedWorkshare(db, hash)
			DeleteWorkerRejection(db, hash)
		}
		DeleteWorksharesForBlock(db, blockNum)
	}
	return nil
}

// WriteBlockRecord stores a block record for tracking
func WriteBlockRecord(db ethdb.KeyValueWriter, record *types.BlockRecord) error {
	if record == nil {
		return nil
	}
	protoRecord := record.ProtoEncode()
	data, err := proto.Marshal(protoRecord)
	if err != nil {
		return err
	}
	return db.Put(blockRecordKey(record.BlockHash), data)
}

// ReadBlockRecord retrieves a block record
func ReadBlockRecord(db ethdb.Reader, hash common.Hash) (*types.BlockRecord, error) {
	data, _ := db.Get(blockRecordKey(hash))
	if len(data) == 0 {
		return nil, nil
	}
	protoRecord := new(types.ProtoBlockRecord)
	if err := proto.Unmarshal(data, protoRecord); err != nil {
		return nil, err
	}
	record := new(types.BlockRecord)
	if err := record.ProtoDecode(protoRecord, db.Location()); err != nil {
		return nil, err
	}
	return record, nil
}

// DeleteBlockRecord removes a block record
func DeleteBlockRecord(db ethdb.KeyValueWriter, hash common.Hash) {
	db.Delete(blockRecordKey(hash))
}

// WriteOrphanedBlock stores an orphaned block record
func WriteOrphanedBlock(db ethdb.KeyValueWriter, record *types.OrphanedBlock) error {
	if record == nil {
		return nil
	}
	protoRecord := record.ProtoEncode()
	data, err := proto.Marshal(protoRecord)
	if err != nil {
		return err
	}
	return db.Put(orphanedBlockKey(record.BlockHash), data)
}

// ReadOrphanedBlock retrieves an orphaned block record
func ReadOrphanedBlock(db ethdb.Reader, hash common.Hash) (*types.OrphanedBlock, error) {
	data, _ := db.Get(orphanedBlockKey(hash))
	if len(data) == 0 {
		return nil, nil
	}
	protoRecord := new(types.ProtoOrphanedBlock)
	if err := proto.Unmarshal(data, protoRecord); err != nil {
		return nil, err
	}
	record := new(types.OrphanedBlock)
	if err := record.ProtoDecode(protoRecord, db.Location()); err != nil {
		return nil, err
	}
	return record, nil
}

// DeleteOrphanedBlock removes an orphaned block record
func DeleteOrphanedBlock(db ethdb.KeyValueWriter, hash common.Hash) {
	db.Delete(orphanedBlockKey(hash))
}

// WriteWorkerRejection stores a worker rejection record
func WriteWorkerRejection(db ethdb.KeyValueWriter, rejection *types.WorkerRejection) error {
	if rejection == nil {
		return nil
	}
	protoRejection := rejection.ProtoEncode()
	data, err := proto.Marshal(protoRejection)
	if err != nil {
		return err
	}
	return db.Put(workerRejectionKey(rejection.WorkshareHash), data)
}

// ReadWorkerRejection retrieves a worker rejection record
func ReadWorkerRejection(db ethdb.Reader, hash common.Hash) (*types.WorkerRejection, error) {
	data, _ := db.Get(workerRejectionKey(hash))
	if len(data) == 0 {
		return nil, nil
	}
	protoRejection := new(types.ProtoWorkerRejection)
	if err := proto.Unmarshal(data, protoRejection); err != nil {
		return nil, err
	}
	rejection := new(types.WorkerRejection)
	if err := rejection.ProtoDecode(protoRejection); err != nil {
		return nil, err
	}
	return rejection, nil
}

// DeleteWorkerRejection removes a worker rejection record
func DeleteWorkerRejection(db ethdb.KeyValueWriter, hash common.Hash) {
	db.Delete(workerRejectionKey(hash))
}

// WriteForkCompetition stores a fork competition record
func WriteForkCompetition(db ethdb.KeyValueWriter, competition *types.ForkCompetition) error {
	if competition == nil {
		return nil
	}
	protoCompetition := competition.ProtoEncode()
	data, err := proto.Marshal(protoCompetition)
	if err != nil {
		return err
	}
	return db.Put(forkCompetitionKey(competition.BlockHash), data)
}

// ReadForkCompetition retrieves a fork competition record
func ReadForkCompetition(db ethdb.Reader, hash common.Hash) (*types.ForkCompetition, error) {
	data, _ := db.Get(forkCompetitionKey(hash))
	if len(data) == 0 {
		return nil, nil
	}
	protoCompetition := new(types.ProtoForkCompetition)
	if err := proto.Unmarshal(data, protoCompetition); err != nil {
		return nil, err
	}
	competition := new(types.ForkCompetition)
	if err := competition.ProtoDecode(protoCompetition); err != nil {
		return nil, err
	}
	return competition, nil
}

// DeleteForkCompetition removes a fork competition record
func DeleteForkCompetition(db ethdb.KeyValueWriter, hash common.Hash) {
	db.Delete(forkCompetitionKey(hash))
}
