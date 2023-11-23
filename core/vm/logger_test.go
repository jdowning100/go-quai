// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"fmt"
	"math/big"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/state"
	"github.com/dominant-strategies/go-quai/core/types"
)

type dummyContractRef struct {
	calledForEach bool
	address       common.Address
}

func (d dummyContractRef) Address() common.Address {
	if (d.address == common.Address{}) {
		return common.ZeroAddr
	} else {
		return d.address
	}
}

func (d *dummyContractRef) SetAddress(a common.Address) {
	d.address = a
}

func (dummyContractRef) Value() *big.Int             { return new(big.Int) }
func (dummyContractRef) SetCode(common.Hash, []byte) {}
func (d *dummyContractRef) ForEachStorage(callback func(key, value common.Hash) bool) {
	d.calledForEach = true
}
func (d *dummyContractRef) SubBalance(amount *big.Int) {}
func (d *dummyContractRef) AddBalance(amount *big.Int) {}
func (d *dummyContractRef) SetBalance(*big.Int)        {}
func (d *dummyContractRef) SetNonce(uint64)            {}
func (d *dummyContractRef) Balance() *big.Int          { return new(big.Int) }

type dummyStatedb struct {
	state.StateDB
}

func (*dummyStatedb) GetRefund() uint64 { return 1337 }

func (d *dummyStatedb) AddLog(log *types.Log)                          { fmt.Printf("%+v\n", log) }
func (d *dummyStatedb) Suicide(common.InternalAddress) bool            { return true }
func (d *dummyStatedb) Exist(common.InternalAddress) bool              { return false }
func (d *dummyStatedb) CreateAccount(common.InternalAddress)           {}
func (d *dummyStatedb) AddRefund(uint64)                               {}
func (d *dummyStatedb) Snapshot() int                                  { return 0 }
func (d *dummyStatedb) GetCode(common.InternalAddress) []byte          { return []byte{} }
func (d *dummyStatedb) GetCodeHash(common.InternalAddress) common.Hash { return common.Hash{} }
func (d *dummyStatedb) AddBalance(common.InternalAddress, *big.Int)    {}
func (d *dummyStatedb) SubBalance(common.InternalAddress, *big.Int)    {}
func (d *dummyStatedb) SetBalance(*big.Int)                            {}
func (d *dummyStatedb) SetNonce(common.InternalAddress, uint64)        {}
func (d *dummyStatedb) GetBalance(common.InternalAddress) *big.Int     { return new(big.Int) }
func (d *dummyStatedb) RevertToSnapshot(int)                           {}
func (d *dummyStatedb) Empty(common.InternalAddress) bool              { return false }
func (d *dummyStatedb) GetState(common.InternalAddress, common.Hash) common.Hash {
	return common.Hash{}
}
func (d *dummyStatedb) SetState(common.InternalAddress, common.Hash, common.Hash) {}
