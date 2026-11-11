// Draws Safeguard's app icon (1024x1024 PNG). Usage: swift make_icon.swift out.png
// Design "J · Radar": a lime sweep over concentric rings on a deep green-black tile.
// The full exploration set lives in Scripts/icon_designs.swift.
import AppKit

let size: CGFloat = 1024
let args = CommandLine.arguments
let out = args.count > 1 ? args[1] : "icon.png"
/// "compact" is for 16-64 px slots: fewer, heavier rings so the mark survives.
let compact = args.count > 2 && args[2] == "compact"

func color(_ hex: UInt32, _ a: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: a)
}

let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size),
                           bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                           colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let ctx = NSGraphicsContext.current!.cgContext
ctx.translateBy(x: 0, y: size)
ctx.scaleBy(x: 1, y: -1)

// Tile on Apple's icon grid (824pt body, centred).
let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
let body = NSBezierPath(roundedRect: tile, xRadius: 185, yRadius: 185)
NSGradient(starting: color(0x08130D), ending: color(0x030605))!.draw(in: body, angle: -90)

// Hairline rim so the edge reads on light desktops.
let rim = NSBezierPath(roundedRect: tile.insetBy(dx: 9, dy: 9), xRadius: 177, yRadius: 177)
NSColor(white: 1, alpha: 0.08).setStroke()
rim.lineWidth = 2
rim.stroke()

let lime = color(0xC9F75C)
let c = CGPoint(x: 512, y: 520)

// Rings.
let rings: [(Double, CGFloat, CGFloat)] = compact
    ? [(242.0, 0.88, 30.0)]
    : [(96.0, 0.34, 9.0), (178.0, 0.48, 10.0), (258.0, 0.64, 11.0)]
for (r, alpha, width) in rings {
    let ring = NSBezierPath(ovalIn: CGRect(x: c.x - r, y: c.y - r, width: r * 2, height: r * 2))
    lime.withAlphaComponent(alpha).setStroke()
    ring.lineWidth = width
    ring.stroke()
}

// Sweep.
let wedge = NSBezierPath()
wedge.move(to: c)
wedge.appendArc(withCenter: c, radius: 258, startAngle: 20, endAngle: 78, clockwise: false)
wedge.close()
NSGraphicsContext.saveGraphicsState()
wedge.addClip()
NSGradient(colors: [lime.withAlphaComponent(compact ? 0.85 : 0.60), lime.withAlphaComponent(0.04)])!
    .draw(fromCenter: c, radius: 0, toCenter: c, radius: 258, options: [])
NSGraphicsContext.restoreGraphicsState()

// Blip and centre.
let blip = CGPoint(x: c.x + cos(52 * .pi / 180) * 178, y: c.y + sin(52 * .pi / 180) * 178)
lime.setFill()
let br: CGFloat = compact ? 42 : 15
NSBezierPath(ovalIn: CGRect(x: blip.x - br, y: blip.y - br, width: br * 2, height: br * 2)).fill()
lime.withAlphaComponent(0.35).setStroke()
let hr: CGFloat = compact ? 76 : 28
let halo = NSBezierPath(ovalIn: CGRect(x: blip.x - hr, y: blip.y - hr, width: hr * 2, height: hr * 2))
halo.lineWidth = compact ? 14 : 5
halo.stroke()
let cr: CGFloat = compact ? 26 : 10
NSBezierPath(ovalIn: CGRect(x: c.x - cr, y: c.y - cr, width: cr * 2, height: cr * 2)).fill()

NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
print("wrote \(out)")
