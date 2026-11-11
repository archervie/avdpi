package ui

import (
	"encoding/hex"
	"fmt"

	"avdpi/internal/capture" // Import the capture package for the Config struct
	"avdpi/internal/parser"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func Start(config capture.Config, packetChan <-chan parser.PacketData) error {
	app := tview.NewApplication()

	// Creating top detail panels
	ethView := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	ethView.SetTitle(" Ethernet Headers ").SetBorder(true)

	ipView := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	ipView.SetTitle(" IP Headers ").SetBorder(true)

	tcpView := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	tcpView.SetTitle(" Transport Headers ").SetBorder(true)

	payloadView := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	payloadView.SetTitle(" Payload Details ").SetBorder(true)

	// Group the panels horizontally
	topFlex := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(ethView, 0, 1, false).
		AddItem(ipView, 0, 1, false).
		AddItem(tcpView, 0, 1, false).
		AddItem(payloadView, 0, 2, false) // Give payload more space

	// Creating table
	table := tview.NewTable().
		SetBorders(true).
		SetSelectable(true, false).
		SetFixed(1, 0)
	headers := []string{"Protocol", "Source", "Destination", "Payload Size"}
	for col, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetExpansion(1)

		table.SetCell(0, col, cell)
	}

	settingsView := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true).
		SetText(fmt.Sprintf(
			"[yellow]Interface Settings:\n\n"+
				"[white]- Interface:  [green]%s\n"+
				"[white]- Filter:     [green]%s\n"+
				"[white]- Read File:  [green]%s\n"+
				"[white]- Save File:  [green]%s\n",
			config.Interface, config.Filter, config.PcapFile, config.SaveResults,
		))
	settingsView.SetTitle(" Configuration ").SetBorder(true)

	// 3. Wire up row selection event
	table.SetSelectionChangedFunc(func(row, column int) {
		if row == 0 {
			if table.GetRowCount() > 1 {
				table.Select(1, 0)
			}
			return // Stop processing the event
		}

		// 2. Normal extraction logic continues here...
		cell := table.GetCell(row, 0)
		if cell == nil || cell.GetReference() == nil {
			return
		}

		packet := cell.GetReference().(parser.PacketData)

		// Update the top panels
		ethView.SetText(fmt.Sprintf("[yellow]Source MAC:[white] %s\n[yellow]Dest MAC:[white] %s", packet.SrcMAC, packet.DstMAC))
		ipView.SetText(fmt.Sprintf("[yellow]Source IP:[white] %s\n[yellow]Dest IP:[white] %s\n[yellow]Payload:[white] %s\n[yellow]TTL:[white] %d\n[yellow]Checksum:[white] %d",
			packet.SrcIP, packet.DstIP, packet.ARPPayload, packet.TTL, packet.IPChecksum))

		tcpView.SetText(
			fmt.Sprintf("[yellow]Source Port:[white] %d\n[yellow]Dest Port:[white] %d\n[yellow]Flags:[white] %s\n[yellow]Checksum:[white] %d\n[yellow]Domain Queried:[white] %s",
				packet.SrcPort, packet.DstPort,
				packet.TCPFlags, packet.TCPChecksum,
				packet.DomainQueried,
			))

		if packet.PayloadSize > 0 {
			// hex.Dump creates a beautiful hex + ASCII view of the raw bytes
			payloadView.SetText(hex.Dump(packet.Payload))
		} else {
			payloadView.SetText("No Application Payload")
		}
	})

	// Group top and bottom vertically
	// The bottom half consists of the table on the left, and settings on the right
	bottomFlex := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(table, 0, 2, true).        // Table takes up 2 parts of the space
		AddItem(settingsView, 0, 1, false) // Settings takes up 1 part

	mainFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(topFlex, 15, 1, false).
		AddItem(bottomFlex, 0, 1, true) // Add bottomFlex instead of table

	// receiver loop
	go func() {
		rowIndex := 1
		for packet := range packetChan {
			app.QueueUpdateDraw(func() {
				src := fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort)
				dst := fmt.Sprintf("%s:%d", packet.DstIP, packet.DstPort)
				size := fmt.Sprintf("%d bytes", packet.PayloadSize)

				// Attach the entire struct to the first cell as a Reference!
				col0 := tview.NewTableCell(packet.Protocol).SetAlign(tview.AlignCenter)
				col0.SetReference(packet)

				table.SetCell(rowIndex, 0, col0)
				table.SetCell(rowIndex, 1, tview.NewTableCell(src).SetAlign(tview.AlignCenter))
				table.SetCell(rowIndex, 2, tview.NewTableCell(dst).SetAlign(tview.AlignCenter))
				table.SetCell(rowIndex, 3, tview.NewTableCell(size).SetAlign(tview.AlignCenter))

				// Scroll table down unless the user has actively selected an older packet
				r, _ := table.GetSelection()
				if r == rowIndex-1 || r == 0 {
					table.Select(rowIndex, 0)
					table.ScrollToEnd()
				}

				rowIndex++
			})
		}
	}()

	if err := app.SetRoot(mainFlex, true).EnableMouse(true).Run(); err != nil {
		return err
	}
	return nil
}
