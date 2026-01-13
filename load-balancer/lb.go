package loadbalancer

import (
	"errors"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type heapData struct {
	connAddr  string
	connCount uint
	conn      *grpc.ClientConn
}

type Heap []heapData

func (h Heap) Len() int           { return len(h) }
func (h Heap) Less(i, j int) bool { return h[i].connCount < h[j].connCount }
func (h Heap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *Heap) Push(x heapData) {
	*h = append(*h, x)
}

func (h *Heap) Pop() heapData {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

type loadBalancer struct {
	mutex sync.Mutex
	heap  *Heap
}

func InitLoadBalancer() loadBalancer {
	return loadBalancer{sync.Mutex{}, &Heap{}}
}

func (lb *loadBalancer) addConnAddr(addr string, connCount uint) error {
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()), // TLS in prod
	)
	if err != nil {
		return err
	}
	lb.heap.Push(heapData{addr, connCount, conn})
	return nil
}

func (lb *loadBalancer) removeConnAddr(addr string) {
	var tmp Heap
	for len(*lb.heap) > 0 {
		currTmp := lb.heap.Pop()

		if currTmp.connAddr == addr {
			for _, data := range tmp {
				lb.heap.Push(data)
			}
			break
		}

		tmp = append(tmp, lb.heap.Pop())
	}
}

func (lb *loadBalancer) pickConnection() (*grpc.ClientConn, error) {
	if len(*lb.heap) == 0 {
		return nil, errors.New("No connections available!")
	}

	outConn := lb.heap.Pop()
	outConn.connCount++
	lb.heap.Push(outConn)

	return outConn.conn, nil
}

func (lb *loadBalancer) loadHandler(srv interface{}, stream grpc.ServerStream) error {
	ctx := stream.Context()

	method, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		return status.Error(codes.Internal, "Method not found!")
	}

	streamConnection, connectionPickErr := lb.pickConnection()
	if connectionPickErr != nil {
		return status.Error(codes.Internal, "Unable to pik a connection!")
	}

	inMD, _ := metadata.FromIncomingContext(ctx)
	outCtx := metadata.NewOutgoingContext(ctx, inMD)

	connectionStream, connStreamErr := grpc.NewClientStream(
		outCtx,
		&grpc.StreamDesc{
			ServerStreams: true,
			ClientStreams: true,
		},
		streamConnection,
		method,
	)
	if connStreamErr != nil {
		return connStreamErr
	}

	if header, err := connectionStream.Header(); err == nil {
		stream.SendHeader(header)
	}

	errCh := make(chan error, 2)

	go func() {
		for {
			var msg []byte
			err := stream.RecvMsg(&msg)
			if err != nil {
				connectionStream.CloseSend()
				errCh <- err
				return
			}
			if err := connectionStream.SendMsg(msg); err != nil {
				errCh <- err
				return
			}
		}
	}()

	go func() {
		for {
			var msg []byte
			err := connectionStream.RecvMsg(&msg)
			if err != nil {
				errCh <- err
				return
			}
			if err := stream.SendMsg(msg); err != nil {
				errCh <- err
				return
			}
		}
	}()

	stream.SetTrailer(connectionStream.Trailer())

	return <-errCh
}
