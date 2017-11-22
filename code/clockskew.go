package main

import (
	"fmt"
	//"log"
	"time"
	"net"
	"encoding/binary"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
	代码完善：
	该部分的代码应该分为两个部分：
		1. 收集时间戳， 将时间戳的信息存放在一个结构体中(该结构体的成员变量包含输出信息)， 将该结构体放入channel中
		2. 信息输出模块， 从channel 中读取信息并存在于文件中
*/

func main() {
	//	获取 libpcap 的版本
	/*
	version := pcap.Version()
	fmt.Println(version)
	//	获取网卡列表*/

	var localIPs map[string]bool = make(map[string]bool)

	iface, _ := net.InterfaceByName("eth0")
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP.To4()
			case *net.IPAddr:
				ip = v.IP.To4()
		}
	
		if ip != nil {
			localIPs[ip.String()] = true
		}
	}


	handle, _ := pcap.OpenLive(
		"eth0",	// device
		int32(65535),	//	snapshot length
		false,	//	promiscuous mode?
		-1 * time.Second,	// timeout 负数表示不缓存，直接输出
	)
	defer handle.Close()


	//handle.SetBPFFilter("tcp and host 111.13.101.208 or host 220.181.57.217 or host  123.125.114.144 or host 10.10.76.10")
	//handle.SetBPFFilter("tcp and port 80")
	handle.SetBPFFilter("tcp and port 443")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP := ip.SrcIP.String()
		dstIP := ip.DstIP.String()

		//_, ok := localIPs[dstIP]
		_, ok := localIPs[srcIP]

		if ok == false{
			continue
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			fmt.Println("ERROR: tcp == nil")
			continue
		}

		tcp, _ := tcpLayer.(*layers.TCP)

		for _, itm := range tcp.Options {
			if itm.OptionType.String() == "Timestamps" {
				srcTcpTimeStamp  := binary.BigEndian.Uint32(itm.OptionData[:4])
				destTcpTimeStamp := binary.BigEndian.Uint32(itm.OptionData[4:8])
			
				fmt.Println(srcIP, dstIP, time.Now().UnixNano(), int(srcTcpTimeStamp), int(destTcpTimeStamp))
			}
		}

	}
}

