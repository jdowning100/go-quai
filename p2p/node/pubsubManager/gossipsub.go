package pubsubManager

import (
	"context"
	"errors"
	"runtime/debug"
	"sync"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"github.com/dominant-strategies/go-quai/cmd/utils"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	p2p "github.com/dominant-strategies/go-quai/p2p"
	"github.com/dominant-strategies/go-quai/p2p/pb"
	"github.com/dominant-strategies/go-quai/quai"
)

const numWorkers = 20   // Number of workers per stream
const msgChanSize = 500 // 500 requests per subscription

var (
	ErrConsensusNotSet     = errors.New("consensus backend not set")
	ErrValidatorFuncNotSet = errors.New("validator function cannot be initialized")
	ErrNoTopic             = errors.New("no topic for requested data")
	ErrUnsupportedType     = errors.New("data type not supported")
)

type PubsubManager struct {
	*pubsub.PubSub
	ctx           context.Context
	subscriptions *sync.Map
	topics        *sync.Map
	consensus     quai.ConsensusAPI
	genesis       common.Hash

	// Callback function to handle received data
	onReceived func(peer.ID, string, string, interface{}, common.Location)
}

// creates a new gossipsub instance
// TODO: what options do we need for quai network? See:
// See https://pkg.go.dev/github.com/libp2p/go-libp2p-pubsub@v0.10.0#Option
func NewGossipSubManager(ctx context.Context, h host.Host) (*PubsubManager, error) {
	cfg := pubsub.DefaultGossipSubParams()
	cfg.D = 30
	cfg.Dlo = 6
	cfg.Dhi = 45
	cfg.Dout = 20
	MaxSize := 3 << 20
	ps, err := pubsub.NewGossipSub(ctx, h, pubsub.WithGossipSubParams(cfg), pubsub.WithMaxMessageSize(MaxSize))
	if err != nil {
		return nil, err
	}
	return &PubsubManager{
		ps,
		ctx,
		new(sync.Map),
		new(sync.Map),
		nil,
		utils.MakeGenesis().ToBlock(0).Hash(),
		nil,
	}, nil
}

func (g *PubsubManager) GetGenesis() common.Hash {
	return g.genesis
}

func (g *PubsubManager) SetQuaiBackend(consensus quai.ConsensusAPI) {
	g.UnsubscribeAll()      // First unsubscribe from existing topics, if already registered
	g.consensus = consensus // Set new backend

}

func (g *PubsubManager) SetReceiveHandler(receiveCb func(peer.ID, string, string, interface{}, common.Location)) {
	g.onReceived = receiveCb
}

func (g *PubsubManager) Stop() error {
	g.UnsubscribeAll()
	return nil
}

func (g *PubsubManager) UnsubscribeAll() {
	g.subscriptions.Range(func(key, value any) bool {
		value.(*pubsub.Subscription).Cancel()
		g.subscriptions.Delete(key)
		return true
	})
	g.topics.Range(func(key, value any) bool {
		value.(*pubsub.Topic).Close()
		g.topics.Delete(key)
		return true
	})
}

// subscribe to broadcasts of the given type of data
func (g *PubsubManager) Subscribe(location common.Location, datatype interface{}) error {
	// build topic name
	topicSub, err := NewTopic(g.genesis, location, datatype)
	if err != nil {
		return err
	}

	// join the topic
	topic, err := g.Join(topicSub.String())
	if err != nil {
		return err
	}
	g.topics.Store(topicSub.String(), topic)
	if g.consensus == nil {
		return ErrConsensusNotSet
	}
	err = g.PubSub.RegisterTopicValidator(topicSub.String(), g.ValidatorFunc())
	if err != nil {
		return ErrValidatorFuncNotSet
	}

	// subscribe to the topic
	subscription, err := topic.Subscribe()
	if err != nil {
		return err
	}
	g.subscriptions.Store(topicSub.String(), subscription)

	go func(location common.Location, sub *pubsub.Subscription) {
		defer func() {
			if r := recover(); r != nil {
				log.Global.WithFields(log.Fields{
					"error":      r,
					"stacktrace": string(debug.Stack()),
					"location":   location.Name(),
				}).Fatal("Go-Quai Panicked")
			}
		}()
		// Create a channel for messages
		msgChan := make(chan *pubsub.Message, msgChanSize)
		// close the msgChan if we exit this function
		defer close(msgChan)
		full := 0
		// maintain a number of worker threads to handle messages
		var msgWorker func(location common.Location)
		msgWorker = func(location common.Location) {
			defer func() {
				if r := recover(); r != nil {
					log.Global.WithFields(log.Fields{
						"error":      r,
						"stacktrace": string(debug.Stack()),
						"location":   location.Name(),
					}).Errorf("Go-Quai Panicked")
				}
				go msgWorker(location) // If this worker exits, start a new one
			}()
			for msg := range msgChan { // This should exit when msgChan is closed
				data := types.ObjectPool.Get()
				data = nil
				// unmarshal the received data depending on the topic's type
				err = pb.UnmarshalAndConvert(msg.Data, location, &data, datatype)
				if err != nil {
					log.Global.Errorf("error unmarshalling data: %s", err)
					continue
				}

				// handle the received data
				if g.onReceived != nil {
					g.onReceived(msg.ReceivedFrom, msg.ID, *msg.Topic, data, location)
				}
			}
		}
		for i := 0; i < numWorkers; i++ {
			go msgWorker(location)
		}
		log.Global.WithField("topic", topic.String()).Debugf("Subscribed to topic")
		for {
			msg, err := sub.Next(g.ctx)
			if err != nil || msg == nil {
				// if context or subscription was cancelled, then we are shutting down
				if g.ctx.Err() != nil || err == pubsub.ErrSubscriptionCancelled {
					return
				}
				log.Global.Errorf("error getting next message from subscription: %s", err)
				continue
			}
			log.Global.Tracef("received message on topic: %s", topicSub.String())

			// Send to worker goroutines
			select {
			case msgChan <- msg:
			default:
				if full%1000 == 0 {
					log.Global.WithField("topic", topicSub.String()).Warnf("message channel full. Lost messages: %d", full)
				}
				full++
			}
		}
	}(location, subscription)

	return nil
}

func (g *PubsubManager) ValidatorFunc() func(ctx context.Context, id p2p.PeerID, msg *pubsub.Message) pubsub.ValidationResult {
	return func(ctx context.Context, id peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		var data interface{}
		topicString := msg.Topic
		if topicString == nil {
			return pubsub.ValidationReject
		}
		topic, err := TopicFromString(*topicString)
		if err != nil {
			return pubsub.ValidationReject
		}
		// get the proto encoded data
		protoData := msg.GetData()

		// get the topic data to be used to decode the proto data
		data = topic.data

		switch data.(type) {
		case *types.WorkObjectBlockView:

			protoWo := new(types.ProtoWorkObjectBlockView)
			err := proto.Unmarshal(protoData, protoWo)
			if err != nil {
				return pubsub.ValidationReject
			}

			block := &types.WorkObjectBlockView{
				WorkObject: &types.WorkObject{},
			}
			err = block.ProtoDecode(protoWo, protoWo.GetWorkObject().GetWoHeader().GetLocation().Value)
			if err != nil {
				return pubsub.ValidationReject
			}

			backend := *g.consensus.GetBackend(topic.location)
			if backend == nil {
				log.Global.WithFields(log.Fields{
					"peer":     id,
					"hash":     block.Hash(),
					"location": block.Location(),
				}).Error("no backend found for this location")
			}
			err = backend.SanityCheckWorkObjectBlockViewBody(block.WorkObject)
			if err != nil {
				backend.Logger().WithField("err", err).Warn("Sanity check of work object failed")
				return pubsub.ValidationReject
			}
			if backend.BadHashExistsInChain() {
				backend.Logger().Warn("Bad Hashes still exist on chain, cannot handle block broadcast yet")
				return pubsub.ValidationIgnore
			}

			// If Block broadcasted by the peer exists in the bad block list drop the peer
			if backend.IsBlockHashABadHash(block.WorkObjectHeader().Hash()) {
				return pubsub.ValidationReject
			}
			return backend.ApplyPoWFilter(block.WorkObject)

		case *types.WorkObjectHeaderView:

			protoWo := new(types.ProtoWorkObjectHeaderView)
			err := proto.Unmarshal(protoData, protoWo)
			if err != nil {
				return pubsub.ValidationReject
			}

			block := &types.WorkObjectHeaderView{
				WorkObject: &types.WorkObject{},
			}
			err = block.ProtoDecode(protoWo, protoWo.GetWorkObject().GetWoHeader().GetLocation().Value)
			if err != nil {
				return pubsub.ValidationReject
			}

			backend := *g.consensus.GetBackend(topic.location)
			if backend == nil {
				log.Global.WithFields(log.Fields{
					"peer":     id,
					"hash":     block.Hash(),
					"location": block.Location(),
				}).Error("no backend found for this location")
			}
			err = backend.SanityCheckWorkObjectHeaderViewBody(block.WorkObject)
			if err != nil {
				backend.Logger().WithField("err", err).Warn("Sanity check of work object header view failed")
				return pubsub.ValidationReject
			}
			if backend.BadHashExistsInChain() {
				backend.Logger().Warn("Bad Hashes still exist on chain, cannot handle block broadcast yet")
				return pubsub.ValidationIgnore
			}

			// If Block broadcasted by the peer exists in the bad block list drop the peer
			if backend.IsBlockHashABadHash(block.WorkObject.WorkObjectHeader().Hash()) {
				return pubsub.ValidationReject
			}
			return backend.ApplyPoWFilter(block.WorkObject)

		case *types.WorkObjectShareView:

			protoWo := new(types.ProtoWorkObjectShareView)
			err := proto.Unmarshal(protoData, protoWo)
			if err != nil {
				return pubsub.ValidationReject
			}

			block := &types.WorkObjectShareView{
				WorkObject: &types.WorkObject{},
			}

			err = block.ProtoDecode(protoWo, protoWo.GetWorkObject().GetWoHeader().GetLocation().Value)
			if err != nil {
				return pubsub.ValidationReject
			}

			backend := *g.consensus.GetBackend(topic.location)
			if backend == nil {
				log.Global.WithFields(log.Fields{
					"peer":     id,
					"hash":     block.Hash(),
					"location": block.Location(),
				}).Error("no backend found for this location")
			}
			// check if the work share is valid before accepting the transactions
			// from the peer
			err = backend.SanityCheckWorkObjectShareViewBody(block.WorkObject)
			if err != nil {
				backend.Logger().WithField("err", err).Warn("Sanity check of work object share view failed")
				return pubsub.ValidationReject
			}
			if validity := backend.CheckIfValidWorkShare(block.WorkObjectHeader()); validity != types.Valid {
				backend.Logger().Error("work share received from peer is not valid")
				return pubsub.ValidationReject
			}

			if len(block.WorkObject.Transactions()) > int(backend.GetMaxTxInWorkShare()) {
				backend.Logger().Error("workshare contains more transactions than allowed")
				return pubsub.ValidationReject
			}
			_, err = backend.Engine().ComputePowHash(block.WorkObject.WorkObjectHeader())
			if err != nil {
				backend.Logger().Error("Error computing the powHash of the work object header received from peer")
				return pubsub.ValidationReject
			}
		}
		return pubsub.ValidationAccept
	}
}

// unsubscribe from broadcasts of the given type of data
func (g *PubsubManager) Unsubscribe(location common.Location, datatype interface{}) error {
	if topic, err := NewTopic(g.genesis, location, datatype); err == nil {
		if value, ok := g.subscriptions.Load(topic.String()); ok {
			value.(*pubsub.Subscription).Cancel()
			g.subscriptions.Delete(topic.String())
		}
		if value, ok := g.topics.Load(topic.String()); ok {
			value.(*pubsub.Topic).Close()
			g.topics.Delete(topic.String())
		}
		return nil
	} else {
		return err
	}
}

// broadcasts data to subscribing peers
func (g *PubsubManager) Broadcast(location common.Location, datatype interface{}) error {
	topicName, err := NewTopic(g.genesis, location, datatype)
	if err != nil {
		return err
	}
	protoData, err := pb.ConvertAndMarshal(datatype)
	if err != nil {
		return err
	}
	if value, ok := g.topics.Load(topicName.String()); ok {
		return value.(*pubsub.Topic).Publish(g.ctx, protoData)
	}
	return ErrNoTopic
}
