package main

import (
    "bufio"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "strconv"
    "strings"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

var (
    snapshotLen int32         = 1024
    promiscuous bool          = false
    err         error
    timeout     time.Duration = 30 * time.Second
    handle      *pcap.Handle

    ipMap  = make(map[string]string)
    macMap = make(map[string]string)

    logEnabled bool = true
    logger     *log.Logger
)

func main() {
    // 创建日志文件
    logFile, err := os.OpenFile("log.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }
    defer logFile.Close()

    // 创建一个新的日志记录器
    logger = log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)

    // 设置输出编码为UTF-8
    logger.SetPrefix("\xEF\xBB\xBF")

    // 获取所有网络接口
    devices, err := pcap.FindAllDevs()
    if err != nil {
        logger.Fatal(err)
    }

    // 打印网卡信息
    fmt.Println("Available network interfaces:")
    for i, device := range devices {
        fmt.Printf("%d. %s\n", i+1, device.Name)
        fmt.Printf("   Description: %s\n", device.Description)
        fmt.Printf("   Flags: %s\n", device.Flags)

        // 打印网卡的IP地址信息
        fmt.Printf("   IP Addresses:\n")
        for _, addr := range device.Addresses {
            if addr.IP.To4() != nil {
                fmt.Printf("     - %s\n", addr.IP.String())
            }
        }

    // 检查网卡是否已经插入线缆
    isConnected := false
    for _, addr := range device.Addresses {
        if addr.IP.IsGlobalUnicast() {
            isConnected = true
            break
        }
    }
    if isConnected {
        fmt.Printf("   Status: Connected\n")
    } else {
        fmt.Printf("   Status: Disconnected\n")
    }

        fmt.Println()
    }

    // 提示用户选择网卡
    fmt.Print("Enter the number of the interface to listen on: ")
    reader := bufio.NewReader(os.Stdin)
    input, _ := reader.ReadString('\n')
    input = strings.TrimSpace(input)

    // 解析用户输入的序号
    index, err := strconv.Atoi(input)
    if err != nil || index < 1 || index > len(devices) {
        logger.Fatal("Invalid interface number")
    }

    // 选择网卡
    device := devices[index-1]
    logger.Print("开始抓包：\r\n")

    // 打开网络接口
    handle, err = pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
    if err != nil {
        logger.Fatal(err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        arpLayer := packet.Layer(layers.LayerTypeARP)
        if arpLayer != nil {
            arpPacket := arpLayer.(*layers.ARP)
            if arpPacket.Operation == layers.ARPReply {
                ip := net.IP(arpPacket.SourceProtAddress).String()
                mac := net.HardwareAddr(arpPacket.SourceHwAddress).String()

                if existingMAC, ok := ipMap[ip]; ok {
                    if existingMAC != mac {
                        logger.Printf("Warning: IP %s has a different MAC address: %s (previously %s)\n", ip, mac, existingMAC)
                    }
                } else {
                    ipMap[ip] = mac
                    if existingIP, ok := macMap[mac]; ok {
                        if existingIP != ip {
                            logger.Printf("Warning: MAC %s has a different IP address: %s (previously %s)\n", mac, ip, existingIP)
                        }
                    } else {
                        macMap[mac] = ip
                        logger.Printf("IP: %s, MAC: %s\n", ip, mac)
                    }
                }
            }
        }
    }
}