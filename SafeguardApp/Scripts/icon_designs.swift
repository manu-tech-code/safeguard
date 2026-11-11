// Draws Safeguard app-icon concepts (1024px masters + a contact sheet).
// Usage: swift Scripts/icon_designs.swift
import AppKit

let S: CGFloat = 1024
let outDir = "build/icons"
try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)

func hex(_ v: UInt32, _ a: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat((v >> 16) & 0xFF) / 255,
            green: CGFloat((v >> 8) & 0xFF) / 255,
            blue: CGFloat(v & 0xFF) / 255, alpha: a)
}

let tile = CGRect(x: 100, y: 100, width: 824, height: 824)

func tilePath() -> NSBezierPath {
    NSBezierPath(roundedRect: tile, xRadius: 185, yRadius: 185)
}

/// Proper shield: flat shoulders, short straight sides, long taper to a point.
func shield(_ r: CGRect) -> NSBezierPath {
    func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
        CGPoint(x: r.minX + x * r.width, y: r.minY + y * r.height)
    }
    let path = NSBezierPath()
    path.move(to: p(0.5, 1.0))
    path.line(to: p(0.965, 0.575))
    path.line(to: p(0.995, 0.36))
    path.line(to: p(0.995, 0.105))
    path.curve(to: p(0.90, 0.0), controlPoint1: p(0.995, 0.035), controlPoint2: p(0.955, 0.0))
    path.line(to: p(0.10, 0.0))
    path.curve(to: p(0.005, 0.105), controlPoint1: p(0.045, 0.0), controlPoint2: p(0.005, 0.035))
    path.line(to: p(0.005, 0.36))
    path.line(to: p(0.035, 0.575))
    path.close()
    return path
}

/// Keyhole punched through a filled shield: round head, tapered stem.
func keyhole(center: CGPoint, r: CGFloat, color: NSColor) {
    color.setFill()
    NSBezierPath(ovalIn: CGRect(x: center.x - r, y: center.y - r, width: r * 2, height: r * 2)).fill()
    let top = center.y + r * 0.62
    let bottom = top + r * 1.30
    let stem = NSBezierPath()
    stem.move(to: CGPoint(x: center.x - r * 0.24, y: top))
    stem.line(to: CGPoint(x: center.x + r * 0.24, y: top))
    stem.line(to: CGPoint(x: center.x + r * 0.40, y: bottom))
    stem.line(to: CGPoint(x: center.x - r * 0.40, y: bottom))
    stem.close()
    stem.fill()
}

func bitmap(_ width: CGFloat = S, _ height: CGFloat? = nil) -> NSBitmapImageRep {
    NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(width), pixelsHigh: Int(height ?? width),
                     bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                     colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
}

func canvas(_ rep: NSBitmapImageRep, size: CGFloat = S, _ body: () -> Void) {
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let ctx = NSGraphicsContext.current!.cgContext
    ctx.translateBy(x: 0, y: size)
    ctx.scaleBy(x: 1, y: -1)
    body()
    NSGraphicsContext.restoreGraphicsState()
}

/// Faint inner hairline so the tile edge reads on light desktops.
func rim(_ width: CGFloat = 2.5, alpha: CGFloat = 0.10) {
    let p = NSBezierPath(roundedRect: tile.insetBy(dx: 9, dy: 9), xRadius: 177, yRadius: 177)
    NSColor(white: 1, alpha: alpha).setStroke()
    p.lineWidth = width
    p.stroke()
}

/// Soft radial sheen top-left, clipped to the tile.
func sheen(_ path: NSBezierPath, alpha: CGFloat = 0.10) {
    NSGraphicsContext.saveGraphicsState()
    path.addClip()
    let g = NSGradient(colorsAndLocations:
        (NSColor(white: 1, alpha: alpha), 0.0),
        (NSColor(white: 1, alpha: 0), 0.55),
        (NSColor(white: 1, alpha: 0), 1.0))!
    g.draw(in: tile, angle: -90)
    NSGraphicsContext.restoreGraphicsState()
}

func save(_ rep: NSBitmapImageRep, _ name: String) {
    let url = URL(fileURLWithPath: "\(outDir)/\(name).png")
    try! rep.representation(using: .png, properties: [:])!.write(to: url)
    print("wrote \(url.path)")
}

// MARK: - A. Graphite shield

func graphite() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x24281F), ending: hex(0x0A0B09))!.draw(in: bg, angle: -90)
        rim()
        let lime = hex(0xC9F75C)
        lime.setFill()
        shield(CGRect(x: 282, y: 292, width: 460, height: 444)).fill()
        keyhole(center: CGPoint(x: 512, y: 446), r: 58, color: hex(0x121410))
    }
    save(rep, "A-graphite")
    return rep
}

// MARK: - B. Pulse

func pulse() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x0F1712), ending: hex(0x050706))!.draw(in: bg, angle: -90)
        NSGraphicsContext.saveGraphicsState()
        bg.addClip()
        hex(0xFFFFFF, 0.05).setFill()
        for x in stride(from: 150.0, through: 870, by: 36) {
            for y in stride(from: 150.0, through: 870, by: 36) {
                NSBezierPath(ovalIn: CGRect(x: x, y: y, width: 2.5, height: 2.5)).fill()
            }
        }
        NSGraphicsContext.restoreGraphicsState()
        rim()

        let lime = hex(0xC9F75C)
        let sh = shield(CGRect(x: 286, y: 268, width: 452, height: 470))
        lime.setStroke()
        sh.lineWidth = 34
        sh.stroke()

        let line = NSBezierPath()
        line.move(to: CGPoint(x: 380, y: 500))
        line.line(to: CGPoint(x: 446, y: 500))
        line.line(to: CGPoint(x: 480, y: 438))
        line.line(to: CGPoint(x: 524, y: 572))
        line.line(to: CGPoint(x: 562, y: 486))
        line.line(to: CGPoint(x: 644, y: 486))
        line.lineWidth = 24
        line.lineCapStyle = .round
        line.lineJoinStyle = .round
        lime.setStroke()
        line.stroke()
        lime.setFill()
        NSBezierPath(ovalIn: CGRect(x: 632, y: 474, width: 25, height: 25)).fill()
    }
    save(rep, "B-pulse")
    return rep
}

// MARK: - C. Gauge

func gauge() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x1B1E24), ending: hex(0x08090B))!.draw(in: bg, angle: -90)
        sheen(bg, alpha: 0.05)
        rim()

        let c = CGPoint(x: 512, y: 524)
        let r: CGFloat = 292
        let track = NSBezierPath()
        track.appendArc(withCenter: c, radius: r, startAngle: 138, endAngle: 402, clockwise: false)
        hex(0xFFFFFF, 0.10).setStroke()
        track.lineWidth = 38
        track.lineCapStyle = .round
        track.stroke()

        let lime = hex(0xC9F75C)
        let arc = NSBezierPath()
        arc.appendArc(withCenter: c, radius: r, startAngle: 138,
                      endAngle: 138 + 264 * 0.74, clockwise: false)
        lime.setStroke()
        arc.lineWidth = 38
        arc.lineCapStyle = .round
        arc.stroke()

        lime.setFill()
        shield(CGRect(x: 402, y: 344, width: 222, height: 260)).fill()
        keyhole(center: CGPoint(x: 513, y: 428), r: 29, color: hex(0x0A0B0C))
    }
    save(rep, "C-gauge")
    return rep
}

// MARK: - D. Dot matrix

func dotMatrix() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        hex(0x050505).setFill()
        bg.fill()
        rim(2, alpha: 0.12)

        let r = CGRect(x: 286, y: 258, width: 452, height: 492)
        let mask = shield(r)
        var chosen: CGPoint? = nil
        var best = CGFloat.greatestFiniteMagnitude
        let target = CGPoint(x: r.minX + r.width * 0.80, y: r.minY + r.height * 0.26)

        NSGraphicsContext.saveGraphicsState()
        mask.addClip()
        let spacing: CGFloat = 25
        let dot: CGFloat = 6.4
        for x in stride(from: r.minX, through: r.maxX, by: spacing) {
            for y in stride(from: r.minY, through: r.maxY, by: spacing) {
                let p = CGPoint(x: x + spacing / 2, y: y + spacing / 2)
                let d = hypot(p.x - target.x, p.y - target.y)
                if d < best { best = d; chosen = p }
                hex(0xEFEBE2, 0.93).setFill()
                NSBezierPath(ovalIn: CGRect(x: p.x - dot, y: p.y - dot, width: dot * 2, height: dot * 2)).fill()
            }
        }
        if let a = chosen {
            hex(0xFF453A).setFill()
            NSBezierPath(ovalIn: CGRect(x: a.x - dot * 1.45, y: a.y - dot * 1.45,
                                        width: dot * 2.9, height: dot * 2.9)).fill()
        }
        NSGraphicsContext.restoreGraphicsState()
    }
    save(rep, "D-dot-matrix")
    return rep
}

// MARK: - E. Field ops

func fieldOps() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x1C1308), ending: hex(0x090603))!.draw(in: bg, angle: -90)
        rim(3, alpha: 0.06)

        let amber = hex(0xFFB02E)
        let b = NSBezierPath()
        let m: CGFloat = 172, arm: CGFloat = 76, t: CGFloat = 18
        for (cx, cy, dx, dy) in [(m, m, 1.0, 1.0), (1024 - m, m, -1.0, 1.0),
                                 (m, 1024 - m, 1.0, -1.0), (1024 - m, 1024 - m, -1.0, -1.0)] {
            b.move(to: CGPoint(x: cx, y: cy))
            b.line(to: CGPoint(x: cx + arm * dx, y: cy))
            b.move(to: CGPoint(x: cx, y: cy))
            b.line(to: CGPoint(x: cx, y: cy + arm * dy))
        }
        amber.setStroke()
        b.lineWidth = t
        b.lineCapStyle = .square
        b.stroke()

        let sh = shield(CGRect(x: 316, y: 274, width: 392, height: 452))
        amber.setStroke()
        sh.lineWidth = 28
        sh.stroke()

        // scan band across the shield
        let bandY: CGFloat = 500
        NSGraphicsContext.saveGraphicsState()
        NSBezierPath(rect: CGRect(x: 316, y: bandY, width: 392, height: 84)).addClip()
        NSGradient(colors: [amber.withAlphaComponent(0), amber.withAlphaComponent(0.28),
                            amber.withAlphaComponent(0)])!
            .draw(in: CGRect(x: 316, y: bandY, width: 392, height: 64), angle: -90)
        NSGraphicsContext.restoreGraphicsState()
        hex(0xFFDDA8).setFill()
        NSBezierPath(rect: CGRect(x: 316, y: bandY + 29, width: 392, height: 7)).fill()
    }
    save(rep, "E-field-ops")
    return rep
}

// MARK: - F. Neo-brutal

func neoBrutal() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        hex(0xF3EFE2).setFill()
        bg.fill()
        rim(3, alpha: 0.10)

        let r = CGRect(x: 300, y: 272, width: 428, height: 472)
        hex(0x111111).setFill()
        shield(r.offsetBy(dx: 26, dy: 26)).fill()

        let sh = shield(r)
        hex(0xD8F45F).setFill()
        sh.fill()
        hex(0x111111).setStroke()
        sh.lineWidth = 26
        sh.stroke()

        keyhole(center: CGPoint(x: 514, y: 452), r: 52, color: hex(0x111111))

        let badge = CGRect(x: 762, y: 172, width: 104, height: 104)
        hex(0xFF5A36).setFill()
        NSBezierPath(ovalIn: badge).fill()
        hex(0x111111).setStroke()
        let o = NSBezierPath(ovalIn: badge)
        o.lineWidth = 16
        o.stroke()
    }
    save(rep, "F-neo-brutal")
    return rep
}

// MARK: - G. Current mark, polished

func current() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0xFF7A4D), ending: hex(0xF2562A))!.draw(in: bg, angle: -90)
        sheen(bg, alpha: 0.12)
        rim(3, alpha: 0.16)
        hex(0x170A05).setFill()
        shield(CGRect(x: 308, y: 286, width: 408, height: 452)).fill()
        keyhole(center: CGPoint(x: 512, y: 452), r: 50, color: hex(0xFF6B3D))
    }
    save(rep, "G-current")
    return rep
}

let designs: [(String, NSBitmapImageRep)] = [
    ("A · Graphite", graphite()),
    ("B · Pulse", pulse()),
    ("C · Gauge", gauge()),
    ("D · Dot matrix", dotMatrix()),
    ("E · Field ops", fieldOps()),
    ("F · Neo-brutal", neoBrutal()),
    ("G · Current, polished", current()),
]

// MARK: - Contact sheet

let cols = 4, rows = 2, cell: CGFloat = 380, gap: CGFloat = 26, pad: CGFloat = 44, label: CGFloat = 46
let sheetW = pad * 2 + CGFloat(cols) * cell + CGFloat(cols - 1) * gap
let sheetH = pad * 2 + CGFloat(rows) * (cell + label) + CGFloat(rows - 1) * gap
let sheet = bitmap(sheetW, sheetH)

func cellOrigin(_ i: Int) -> CGPoint {
    CGPoint(x: pad + CGFloat(i % cols) * (cell + gap),
            y: pad + CGFloat(i / cols) * (cell + label + gap))
}

// Backgrounds in the flipped (top-left) space; images and text go in a second,
// native-space pass so nothing is drawn upside down.
canvas(sheet, size: sheetH) {
    hex(0x111311).setFill()
    NSBezierPath(rect: CGRect(x: 0, y: 0, width: sheetW, height: sheetH)).fill()

    let o = cellOrigin(7)
    let cellRect = CGRect(x: o.x, y: o.y, width: cell, height: cell)
    hex(0x1B1D1A).setFill()
    NSBezierPath(roundedRect: cellRect, xRadius: 26, yRadius: 26).fill()
    hex(0xEDEAE2).setFill()
    NSBezierPath(roundedRect: CGRect(x: cellRect.minX + 22, y: cellRect.minY + 292,
                                     width: cellRect.width - 44, height: 66),
                 xRadius: 12, yRadius: 12).fill()
}

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: sheet)

func drawIcon(_ rep: NSBitmapImageRep, in rect: CGRect) {
    let img = NSImage(size: NSSize(width: 1024, height: 1024))
    img.addRepresentation(rep)
    img.draw(in: CGRect(x: rect.minX, y: sheetH - rect.maxY, width: rect.width, height: rect.height))
}

for (i, item) in designs.enumerated() {
    let o = cellOrigin(i)
    drawIcon(item.1, in: CGRect(x: o.x, y: o.y, width: cell, height: cell))
}

// eighth cell: legibility at Dock sizes, dark and light
let o = cellOrigin(7)
let samples = [designs[0], designs[6]]
for (col, sample) in samples.enumerated() {
    let x = o.x + 40 + CGFloat(col) * 186
    var y = o.y + 34
    for side in [132.0, 72.0, 44.0] as [CGFloat] {
        drawIcon(sample.1, in: CGRect(x: x, y: y, width: side, height: side))
        y += side + 44
    }
}

// Labels
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: sheet)
func label(_ text: String, at point: CGPoint) {
    let attrs: [NSAttributedString.Key: Any] = [
        .font: NSFont.systemFont(ofSize: 26, weight: .semibold),
        .foregroundColor: hex(0xE9E7DF),
    ]
    NSAttributedString(string: text, attributes: attrs).draw(at: point)
}
for (i, item) in designs.enumerated() {
    let o = cellOrigin(i)
    label(item.0, at: CGPoint(x: o.x + 6, y: sheetH - (o.y + cell) - label + 12))
}
let last = cellOrigin(7)
label("H · Dock sizes", at: CGPoint(x: last.x + 6, y: sheetH - (last.y + cell) - label + 12))
NSGraphicsContext.restoreGraphicsState()
save(sheet, "contact-sheet")

// =====================================================================
// MARK: - Round two: ten more directions
// =====================================================================

func padlock() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x171B14), ending: hex(0x090B08))!.draw(in: bg, angle: -90)
        rim()
        let lime = hex(0xC9F75C)
        let shackle = NSBezierPath()
        shackle.appendArc(withCenter: CGPoint(x: 512, y: 556), radius: 128,
                          startAngle: 180, endAngle: 360, clockwise: false)
        lime.setStroke()
        shackle.lineWidth = 52
        shackle.lineCapStyle = .round
        shackle.stroke()

        lime.setFill()
        NSBezierPath(roundedRect: CGRect(x: 338, y: 512, width: 348, height: 288),
                     xRadius: 76, yRadius: 76).fill()
        keyhole(center: CGPoint(x: 512, y: 606), r: 48, color: hex(0x10130E))
    }
    save(rep, "H-padlock")
    return rep
}

func eyeShield() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x0C1411), ending: hex(0x050807))!.draw(in: bg, angle: -90)
        rim()
        let lime = hex(0xC9F75C)
        let sh = shield(CGRect(x: 288, y: 266, width: 448, height: 478))
        lime.setStroke()
        sh.lineWidth = 32
        sh.stroke()

        let eye = NSBezierPath()
        eye.move(to: CGPoint(x: 372, y: 486))
        eye.curve(to: CGPoint(x: 652, y: 486), controlPoint1: CGPoint(x: 448, y: 408),
                  controlPoint2: CGPoint(x: 576, y: 408))
        eye.curve(to: CGPoint(x: 372, y: 486), controlPoint1: CGPoint(x: 576, y: 564),
                  controlPoint2: CGPoint(x: 448, y: 564))
        eye.close()
        lime.setFill()
        eye.fill()
        hex(0x0A1410).setFill()
        NSBezierPath(ovalIn: CGRect(x: 464, y: 438, width: 96, height: 96)).fill()
        hex(0xC9F75C).setFill()
        NSBezierPath(ovalIn: CGRect(x: 486, y: 456, width: 30, height: 30)).fill()
    }
    save(rep, "I-eye-shield")
    return rep
}

func radar() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x08130D), ending: hex(0x030605))!.draw(in: bg, angle: -90)
        rim(2, alpha: 0.08)
        let c = CGPoint(x: 512, y: 520)
        let lime = hex(0xC9F75C)

        for (r, alpha, width) in [(96.0, 0.22, 7.0), (178.0, 0.34, 7.0), (258.0, 0.50, 8.0)] {
            let ring = NSBezierPath(ovalIn: CGRect(x: c.x - r, y: c.y - r, width: r * 2, height: r * 2))
            lime.withAlphaComponent(alpha).setStroke()
            ring.lineWidth = width
            ring.stroke()
        }

        // sweep wedge
        let wedge = NSBezierPath()
        wedge.move(to: c)
        wedge.appendArc(withCenter: c, radius: 258, startAngle: 20, endAngle: 78, clockwise: false)
        wedge.close()
        NSGraphicsContext.saveGraphicsState()
        wedge.addClip()
        NSGradient(colors: [lime.withAlphaComponent(0.48), lime.withAlphaComponent(0.02)])!
            .draw(fromCenter: c, radius: 0, toCenter: c, radius: 258, options: [])
        NSGraphicsContext.restoreGraphicsState()

        let blip = CGPoint(x: c.x + cos(52 * .pi / 180) * 178, y: c.y + sin(52 * .pi / 180) * 178)
        lime.setFill()
        NSBezierPath(ovalIn: CGRect(x: blip.x - 13, y: blip.y - 13, width: 26, height: 26)).fill()
        lime.withAlphaComponent(0.35).setStroke()
        let halo = NSBezierPath(ovalIn: CGRect(x: blip.x - 26, y: blip.y - 26, width: 52, height: 52))
        halo.lineWidth = 5
        halo.stroke()

        lime.setFill()
        NSBezierPath(ovalIn: CGRect(x: c.x - 8, y: c.y - 8, width: 16, height: 16)).fill()
    }
    save(rep, "J-radar")
    return rep
}

func keyMark() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x14170F), ending: hex(0x070806))!.draw(in: bg, angle: -90)
        rim()
        let lime = hex(0xC9F75C)

        let head = NSBezierPath(ovalIn: CGRect(x: 556, y: 282, width: 196, height: 196))
        lime.setStroke()
        head.lineWidth = 46
        head.stroke()

        let shaft = NSBezierPath()
        shaft.move(to: CGPoint(x: 590, y: 452))
        shaft.line(to: CGPoint(x: 322, y: 720))
        shaft.lineWidth = 46
        shaft.lineCapStyle = .round
        shaft.stroke()

        // teeth
        for (t, len) in [(0.46, 72.0), (0.66, 96.0)] {
            let px = 590 + (322 - 590) * t
            let py = 452 + (720 - 452) * t
            let tooth = NSBezierPath()
            tooth.move(to: CGPoint(x: px, y: py))
            tooth.line(to: CGPoint(x: px + len * 0.72, y: py + len * 0.72))
            tooth.lineWidth = 40
            tooth.lineCapStyle = .round
            tooth.stroke()
        }
    }
    save(rep, "K-key")
    return rep
}

func checkShield() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x171B13), ending: hex(0x090B07))!.draw(in: bg, angle: -90)
        rim()
        hex(0xC9F75C).setFill()
        shield(CGRect(x: 292, y: 282, width: 440, height: 458)).fill()
        let check = NSBezierPath()
        check.move(to: CGPoint(x: 412, y: 508))
        check.line(to: CGPoint(x: 486, y: 584))
        check.line(to: CGPoint(x: 626, y: 424))
        check.lineWidth = 54
        check.lineCapStyle = .round
        check.lineJoinStyle = .round
        hex(0x0F1309).setStroke()
        check.stroke()
    }
    save(rep, "L-check-shield")
    return rep
}

func beacon() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x0A1520), ending: hex(0x03070A))!.draw(in: bg, angle: -90)
        rim(2, alpha: 0.10)
        let lime = hex(0xC9F75C)

        // beams
        for direction in [-1.0, 1.0] {
            let beam = NSBezierPath()
            beam.move(to: CGPoint(x: 512, y: 322))
            beam.line(to: CGPoint(x: 512 + 300 * direction, y: 208))
            beam.line(to: CGPoint(x: 512 + 300 * direction, y: 470))
            beam.close()
            NSGraphicsContext.saveGraphicsState()
            beam.addClip()
            NSGradient(colors: [lime.withAlphaComponent(0.42), lime.withAlphaComponent(0)])!
                .draw(fromCenter: CGPoint(x: 512, y: 322), radius: 0,
                      toCenter: CGPoint(x: 512, y: 322), radius: 340, options: [])
            NSGraphicsContext.restoreGraphicsState()
        }

        // mast
        lime.setFill()
        NSBezierPath(roundedRect: CGRect(x: 492, y: 360, width: 40, height: 386),
                     xRadius: 10, yRadius: 10).fill()
        // lamp
        NSBezierPath(ovalIn: CGRect(x: 478, y: 286, width: 68, height: 68)).fill()
        hex(0x0A1520).setFill()
        NSBezierPath(ovalIn: CGRect(x: 494, y: 302, width: 36, height: 36)).fill()

        // water
        lime.withAlphaComponent(0.55).setStroke()
        for (i, w) in [200.0, 300.0, 400.0].enumerated() {
            let wave = NSBezierPath()
            wave.appendArc(withCenter: CGPoint(x: 512, y: 806), radius: w,
                           startAngle: 205, endAngle: 335, clockwise: false)
            wave.lineWidth = CGFloat(10 - i * 2)
            wave.stroke()
        }
    }
    save(rep, "M-beacon")
    return rep
}

func hexSentinel() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x14171A), ending: hex(0x070809))!.draw(in: bg, angle: -90)
        rim()
        let lime = hex(0xC9F75C)
        let c = CGPoint(x: 512, y: 520)
        let hexagon = NSBezierPath()
        for i in 0..<6 {
            let a = (CGFloat(30 + i * 60)) * .pi / 180
            let p = CGPoint(x: c.x + cos(a) * 292, y: c.y + sin(a) * 292)
            i == 0 ? hexagon.move(to: p) : hexagon.line(to: p)
        }
        hexagon.close()
        lime.setStroke()
        hexagon.lineWidth = 34
        hexagon.lineJoinStyle = .round
        hexagon.stroke()

        lime.setFill()
        NSBezierPath(ovalIn: CGRect(x: c.x - 46, y: c.y - 66, width: 92, height: 92)).fill()
        let stem = NSBezierPath()
        stem.move(to: CGPoint(x: c.x - 22, y: c.y + 20))
        stem.line(to: CGPoint(x: c.x + 22, y: c.y + 20))
        stem.line(to: CGPoint(x: c.x + 34, y: c.y + 96))
        stem.line(to: CGPoint(x: c.x - 34, y: c.y + 96))
        stem.close()
        stem.fill()

        let alert = CGRect(x: 712, y: 236, width: 74, height: 74)
        hex(0xFF5A36).setFill()
        NSBezierPath(ovalIn: alert).fill()
    }
    save(rep, "N-hex-sentinel")
    return rep
}

func glassShield() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x0A1A18), ending: hex(0x050C0B))!.draw(in: bg, angle: -90)
        sheen(bg, alpha: 0.06)
        rim(3, alpha: 0.10)

        let body = shield(CGRect(x: 292, y: 278, width: 440, height: 462))
        NSGraphicsContext.saveGraphicsState()
        body.addClip()
        NSGradient(starting: hex(0xD9FF88), ending: hex(0x3BC6B4))!.draw(in: bg, angle: -90)
        // a single soft light from above, fading with no hard band
        let light = NSGradient(colorsAndLocations:
            (NSColor(white: 1, alpha: 0.30), 0.0),
            (NSColor(white: 1, alpha: 0.06), 0.45),
            (NSColor(white: 1, alpha: 0), 0.80))!
        light.draw(in: CGRect(x: 292, y: 278, width: 440, height: 462), angle: -90)
        NSGraphicsContext.restoreGraphicsState()

        NSColor(white: 1, alpha: 0.30).setStroke()
        body.lineWidth = 5
        body.stroke()

        keyhole(center: CGPoint(x: 512, y: 448), r: 50, color: hex(0x07211D))
    }
    save(rep, "O-glass-shield")
    return rep
}

func binaryShield() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        hex(0x060807).setFill()
        bg.fill()
        rim(2, alpha: 0.10)

        let r = CGRect(x: 296, y: 262, width: 432, height: 480)
        let mask = shield(r)
        var cells: [CGRect] = []
        NSGraphicsContext.saveGraphicsState()
        mask.addClip()
        let xStep: CGFloat = 40, yStep: CGFloat = 40
        var row = 0
        for y in stride(from: r.minY + 12, through: r.maxY, by: yStep) {
            var col = 0
            for x in stride(from: r.minX + 12, through: r.maxX, by: xStep) {
                let alpha = 0.30 + 0.65 * (1 - y / r.maxY)
                hex(0xC9F75C, alpha).setFill()
                let w: CGFloat = (col % 3 == 0) ? 28 : 20
                NSBezierPath(roundedRect: CGRect(x: x, y: y, width: w, height: 12),
                             xRadius: 5, yRadius: 5).fill()
                cells.append(CGRect(x: x, y: y, width: w, height: 12))
                _ = col
                col += 1
            }
            row += 1
        }
        // one corrupted-looking cell
        if let bad = cells.first(where: { $0.midX > r.midX + 40 && $0.midY < r.minY + 150 }) {
            hex(0xFF5A36, 1).setFill()
            NSBezierPath(roundedRect: bad, xRadius: 4, yRadius: 4).fill()
        }
        NSGraphicsContext.restoreGraphicsState()
        _ = row
    }
    save(rep, "P-binary-shield")
    return rep
}

func alertShield() -> NSBitmapImageRep {
    let rep = bitmap()
    canvas(rep) {
        let bg = tilePath()
        NSGradient(starting: hex(0x161A12), ending: hex(0x080A07))!.draw(in: bg, angle: -90)
        rim()
        hex(0xC9F75C).setFill()
        shield(CGRect(x: 300, y: 280, width: 424, height: 456)).fill()

        let badge = CGRect(x: 636, y: 690, width: 172, height: 172)
        hex(0xFF5A36).setFill()
        NSBezierPath(ovalIn: badge).fill()
        hex(0x2B0D05).setFill()
        NSBezierPath(roundedRect: CGRect(x: badge.midX - 13, y: badge.midY - 52,
                                         width: 26, height: 68),
                     xRadius: 12, yRadius: 12).fill()
        NSBezierPath(ovalIn: CGRect(x: badge.midX - 14, y: badge.midY + 30,
                                    width: 28, height: 28)).fill()
    }
    save(rep, "Q-alert-shield")
    return rep
}

let designs2: [(String, NSBitmapImageRep)] = [
    ("H · Padlock", padlock()),
    ("I · Eye shield", eyeShield()),
    ("J · Radar", radar()),
    ("K · Key", keyMark()),
    ("L · Check shield", checkShield()),
    ("M · Beacon", beacon()),
    ("N · Hex sentinel", hexSentinel()),
    ("O · Glass shield", glassShield()),
    ("P · Binary shield", binaryShield()),
    ("Q · Alert shield", alertShield()),
]

let cols2 = 4, rows2 = 3, cell2: CGFloat = 360, gap2: CGFloat = 26, pad2: CGFloat = 44, label2: CGFloat = 46
let sheet2W = pad2 * 2 + CGFloat(cols2) * cell2 + CGFloat(cols2 - 1) * gap2
let sheet2H = pad2 * 2 + CGFloat(rows2) * (cell2 + label2) + CGFloat(rows2 - 1) * gap2
let sheet2 = bitmap(sheet2W, sheet2H)

func cellOrigin2(_ i: Int) -> CGPoint {
    CGPoint(x: pad2 + CGFloat(i % cols2) * (cell2 + gap2),
            y: pad2 + CGFloat(i / cols2) * (cell2 + label2 + gap2))
}

/// Top-left rectangle -> bottom-left (AppKit) rectangle.
func fromTop(_ x: CGFloat, _ yTop: CGFloat, _ w: CGFloat, _ h: CGFloat) -> CGRect {
    CGRect(x: x, y: sheet2H - yTop - h, width: w, height: h)
}

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: sheet2)

hex(0x111311).setFill()
NSBezierPath(rect: CGRect(x: 0, y: 0, width: sheet2W, height: sheet2H)).fill()

func draw2(_ rep: NSBitmapImageRep, _ x: CGFloat, _ yTop: CGFloat, _ side: CGFloat) {
    let img = NSImage(size: NSSize(width: 1024, height: 1024))
    img.addRepresentation(rep)
    img.draw(in: fromTop(x, yTop, side, side))
}

for (i, item) in designs2.enumerated() {
    let o = cellOrigin2(i)
    draw2(item.1, o.x, o.y, cell2)
}

// Dock sizes cell
let sizeCell = cellOrigin2(10)
hex(0x1B1D1A).setFill()
NSBezierPath(roundedRect: fromTop(sizeCell.x, sizeCell.y, cell2, cell2),
             xRadius: 26, yRadius: 26).fill()
let picks = [designs2[0], designs2[4], designs2[9]]
hex(0xEDEAE2).setFill()
NSBezierPath(roundedRect: fromTop(sizeCell.x + 22, sizeCell.y + 250, cell2 - 44, 84),
             xRadius: 12, yRadius: 12).fill()
for (i, sample) in picks.enumerated() {
    let x = sizeCell.x + 40 + CGFloat(i) * 100
    draw2(sample.1, x, sizeCell.y + 46, 88)
    draw2(sample.1, x + 10, sizeCell.y + 268, 44)
}

// Pairing cell
let pairCell = cellOrigin2(11)
hex(0x1B1D1A).setFill()
NSBezierPath(roundedRect: fromTop(pairCell.x, pairCell.y, cell2, cell2),
             xRadius: 26, yRadius: 26).fill()
draw2(designs[6].1, pairCell.x + 40, pairCell.y + 58, 128)
draw2(designs2[9].1, pairCell.x + 192, pairCell.y + 58, 128)
draw2(designs2[0].1, pairCell.x + 40, pairCell.y + 206, 128)
draw2(designs2[4].1, pairCell.x + 192, pairCell.y + 206, 128)

// Labels (native space)
let attrs2: [NSAttributedString.Key: Any] = [
    .font: NSFont.systemFont(ofSize: 24, weight: .semibold),
    .foregroundColor: hex(0xE9E7DF),
]
for (i, item) in designs2.enumerated() {
    let o = cellOrigin2(i)
    NSAttributedString(string: item.0, attributes: attrs2)
        .draw(at: CGPoint(x: o.x + 6, y: sheet2H - (o.y + cell2) - label2 + 12))
}
NSAttributedString(string: "Dock sizes", attributes: attrs2)
    .draw(at: CGPoint(x: sizeCell.x + 6, y: sheet2H - (sizeCell.y + cell2) - label2 + 12))
NSAttributedString(string: "With the coral mark", attributes: attrs2)
    .draw(at: CGPoint(x: pairCell.x + 6, y: sheet2H - (pairCell.y + cell2) - label2 + 12))
NSGraphicsContext.restoreGraphicsState()
save(sheet2, "contact-sheet-2")
