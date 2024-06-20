package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/xuri/excelize/v2"
)

var (
    snapshotLen int32         = 1024
    promiscuous bool          = false
    err         error
    timeout     time.Duration = 30 * time.Second
    handle      *pcap.Handle

    ipMap       = make(map[string]string)
    macMap      = make(map[string][]string)
    macVendorMap = make(map[string]string)

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

                if _, ok := ipMap[ip]; !ok {
                    ipMap[ip] = mac
                }

                if _, ok := macMap[mac]; !ok {
                    macMap[mac] = []string{}
                    macVendorMap[mac] = getVendor(mac)
                }

                if !contains(macMap[mac], ip) {
                    macMap[mac] = append(macMap[mac], ip)
                }

                // 包含厂商信息的结构
                jsonData := make(map[string]interface{})
                for mac, ips := range macMap {
                    jsonData[mac] = map[string]interface{}{
                        "ips":    ips,
                        "vendor": macVendorMap[mac],
                    }
                }

                data, err := json.MarshalIndent(jsonData, "", "  ")
                if err != nil {
                    logger.Printf("Error marshalling JSON: %s\n", err)
                    continue
                }

                err = os.WriteFile("lanipcollect.json", data, 0644)
                if err != nil {
                    logger.Printf("Error writing JSON file: %s\n", err)
                }

                logger.Printf("Updated mapping: MAC %s (%s) - IP %s\n", mac, macVendorMap[mac], ip)
                writeToExcel(macMap, macVendorMap)
            }
        }
    }
}

func contains(slice []string, item string) bool {
    for _, v := range slice {
        if v == item {
            return true
        }
    }
    return false
}

func getVendor(mac string) string {
    macRegex := regexp.MustCompile(`(?i)(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}`)
    if macRegex.MatchString(mac) {
        mac = strings.ReplaceAll(mac, ":", "-")
        mac = strings.ToUpper(mac)
        if len(mac) >= 8 {
            mac = mac[:8]
        } else {
            return "Unknown"
        }

        file, err := os.Open("oui.txt")
        if err != nil {
            fmt.Println("Error opening file:", err)
            os.Exit(1)
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        var organization string
        for scanner.Scan() {
            line := scanner.Text()
            if strings.Contains(line, mac) && strings.Contains(line, "(hex)") {
                organization = strings.TrimSpace(strings.Split(line, "(hex)")[1])
                break
            }
        }

        if err := scanner.Err(); err != nil {
            fmt.Println("Error reading file:", err)
            os.Exit(1)
        }

        if organization != "" {
            return organization
        }
    }
    return "Unknown"
}

func writeToExcel(macMap map[string][]string, macVendorMap map[string]string) {
    f := excelize.NewFile()
    sheet := "Sheet1"

    // 设置表头
    f.SetCellValue(sheet, "A1", "序号")
    f.SetCellValue(sheet, "B1", "MAC地址")
    f.SetCellValue(sheet, "C1", "IP地址")
    f.SetCellValue(sheet, "D1", "厂商")

    // 收集和排序数据
    type MacEntry struct {
        Mac     string
        Ips     []string
        Vendor  string
    }

    var entries []MacEntry
    for mac, ips := range macMap {
        // 按IP地址最后一个8bit排序
        sort.Slice(ips, func(i, j int) bool {
            return getLast8Bits(ips[i]) < getLast8Bits(ips[j])
        })
        entries = append(entries, MacEntry{
            Mac:    mac,
            Ips:    ips,
            Vendor: macVendorMap[mac],
        })
    }

    // 按第一个IP地址的最后一个8bit排序
    sort.Slice(entries, func(i, j int) bool {
        return getLast8Bits(entries[i].Ips[0]) < getLast8Bits(entries[j].Ips[0])
    })

    // 写入数据
    row := 2
    for i, entry := range entries {
        f.SetCellValue(sheet, fmt.Sprintf("A%d", row), i+1)
        f.SetCellValue(sheet, fmt.Sprintf("B%d", row), entry.Mac)
        f.SetCellValue(sheet, fmt.Sprintf("C%d", row), strings.Join(entry.Ips, " "))
        f.SetCellValue(sheet, fmt.Sprintf("D%d", row), entry.Vendor)
        row++
    }

    if err := f.SaveAs("lanipcollect.xlsx"); err != nil {
        log.Fatalf("Error saving Excel file: %s\n", err)
    }
}

func getLast8Bits(ip string) int {
    parts := strings.Split(ip, ".")
    if len(parts) != 4 {
        return 0
    }
    lastPart, err := strconv.Atoi(parts[3])
    if err != nil {
        return 0
    }
    return lastPart
}
