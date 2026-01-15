package main

import (
	loadbalancer "mrnet/load-balancer"
	"net"

	"google.golang.org/grpc"
)

func main() {
	lb := loadbalancer.LoadBalancer()
	lb.AddConnAddr(":6066", 0)

	server := grpc.NewServer(
		grpc.UnknownServiceHandler(lb.LoadHandler),
	)

	lis, _ := net.Listen("tcp", ":5000")
	server.Serve(lis)
}
