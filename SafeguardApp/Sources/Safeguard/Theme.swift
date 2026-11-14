import AppKit
import CoreText
import SwiftUI

// MARK: - Theme
//
// Components read colours and rules from the current skin (see Looks.swift) as they draw.

enum Theme {
    /// Set by AppStore whenever the look changes; the root view is rebuilt after that.
    static var look: Look = .bento { didSet { skin = look.skin } }
    static var skin: Skin = Look.bento.skin
    static var ops: Bool { look == .fieldops }

    private static func c(_ hex: UInt32) -> Color { Color(hex: hex) }

    static var bg: Color { c(skin.bg) }
    static var tile: Color { c(skin.tile) }
    static var inset: Color { c(skin.inset) }
    static var insetHover: Color { c(skin.insetHover) }
    static var well: Color { c(skin.well) }
    static var line: Color { c(skin.line) }
    static var rule: Color { c(skin.rule) }
    /// Outlines of buttons and fields.
    static var edge: Color { c(skin.edge) }

    static var text: Color { c(skin.text) }
    static var text2: Color { c(skin.text2) }
    static var text3: Color { c(skin.text3) }
    static var dim: Color { c(skin.dim) }

    /// The brand colour for fills, and the same colour for text.
    static var accent: Color { c(skin.accent) }
    static var accentHover: Color { c(skin.accentHover) }
    static var accentInk: Color { c(skin.accentInk) }
    static var accentText: Color { c(skin.accentText) }
    static var red: Color { c(skin.red) }
    static var amber: Color { c(skin.amber) }
    static var green: Color { c(skin.green) }
    static var blue: Color { c(skin.blue) }
    static var gray: Color { text3 }
    static var sparkBase: Color { c(skin.spark) }
    /// Ink on bright fills, and the bright "something is off" fill with its ink.
    static var onFill: Color { c(skin.onFill) }
    static var warnFill: Color { c(skin.warnFill) }
    static var warnInk: Color { c(skin.warnInk) }

    static var windowBackground: NSColor {
        let h = skin.bg
        return NSColor(srgbRed: CGFloat((h >> 16) & 0xFF) / 255, green: CGFloat((h >> 8) & 0xFF) / 255,
                       blue: CGFloat(h & 0xFF) / 255, alpha: 1)
    }

    /// Corner radius for this look.
    static func corner(_ r: CGFloat) -> CGFloat { r * skin.radiusScale }
}

extension Color {
    init(hex: UInt32) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xFF) / 255,
                  green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255,
                  opacity: 1)
    }
}

extension Severity {
    /// The bright fill behind a finding's header block (paper looks use poster colours).
    var fill: Color {
        guard Theme.look == .brutal else { return color }
        switch self {
        case .high: return Color(hex: 0xFF5A4E)
        case .medium: return Theme.warnFill
        case .low: return Color(hex: 0x8FD3FF)
        case .info: return Theme.inset
        }
    }

    var color: Color {
        switch self {
        case .high: Theme.red
        case .medium: Theme.amber
        case .low: Theme.blue
        case .info: Theme.text3
        }
    }
}

/// The hero block's colour and ink for each overall state. Looks with a plain hero use `hero` for
/// text and bars, and ordinary text colours for the ink.
extension ThreatLevel {
    private var index: Int {
        switch self {
        case .secure: 0
        case .watch: 1
        case .danger: 2
        }
    }
    var hero: Color { Color(hex: Theme.skin.hero[index]) }
    var heroInk: Color { Color(hex: Theme.skin.heroInk[index]) }
    var heroInkSoft: Color { Color(hex: Theme.skin.heroSoft[index]) }

    var badge: String {
        switch self {
        case .secure: "All clear"
        case .watch: "Needs attention"
        case .danger: "Under threat"
        }
    }
}

extension View {
    /// Small labels are capitals in some looks; `control` marks buttons, headings and navigation,
    /// which are capitals in fewer. Paths, URLs and messages never are.
    func labelCase(tracking: CGFloat = 1, control: Bool = false) -> some View {
        let caps = control ? Theme.skin.capsControls : Theme.skin.capsLabels
        return textCase(caps ? .uppercase : nil).tracking(caps ? tracking : 0)
    }
}

// MARK: - Shapes

/// A capsule when the radius is large, otherwise a rounded rectangle (a plain rectangle at 0).
struct CapShape: InsettableShape {
    var radius: CGFloat
    var inset: CGFloat = 0
    func path(in rect: CGRect) -> Path {
        let r = rect.insetBy(dx: inset, dy: inset)
        let half = min(r.width, r.height) / 2
        if radius >= half { return RoundedRectangle(cornerRadius: half, style: .circular).path(in: r) }
        if radius <= 0 { return Path(r) }
        return RoundedRectangle(cornerRadius: radius, style: .continuous).path(in: r)
    }
    func inset(by amount: CGFloat) -> CapShape { CapShape(radius: radius, inset: inset + amount) }
}

/// Buttons, chips and fields.
struct PillShape: InsettableShape {
    var inset: CGFloat = 0
    func path(in rect: CGRect) -> Path { CapShape(radius: Theme.skin.pillRadius, inset: inset).path(in: rect) }
    func inset(by amount: CGFloat) -> PillShape { PillShape(inset: inset + amount) }
}

/// Round icon buttons and badges.
struct RoundShape: InsettableShape {
    var inset: CGFloat = 0
    func path(in rect: CGRect) -> Path { CapShape(radius: Theme.skin.roundRadius, inset: inset).path(in: rect) }
    func inset(by amount: CGFloat) -> RoundShape { RoundShape(inset: inset + amount) }
}

/// Status dots.
struct DotShape: InsettableShape {
    var inset: CGFloat = 0
    func path(in rect: CGRect) -> Path { CapShape(radius: Theme.skin.dotRadius, inset: inset).path(in: rect) }
    func inset(by amount: CGFloat) -> DotShape { DotShape(inset: inset + amount) }
}

/// A 1px rule: solid, dashed or dotted, as used between rows.
struct RuleLine: View {
    var style: RowStyle = Theme.skin.rows
    var color: Color = Theme.rule

    var body: some View {
        Rectangle().fill(.clear).frame(height: 1)
            .overlay(Line().stroke(color, style: stroke))
    }

    private var stroke: StrokeStyle {
        switch style {
        case .dashed: StrokeStyle(lineWidth: 1, dash: [3, 3])
        case .dotted: StrokeStyle(lineWidth: 1.6, lineCap: .round, dash: [0.1, 4])
        default: StrokeStyle(lineWidth: 1)
        }
    }

    private struct Line: Shape {
        func path(in r: CGRect) -> Path {
            var p = Path(); p.move(to: CGPoint(x: 0, y: r.midY)); p.addLine(to: CGPoint(x: r.maxX, y: r.midY)); return p
        }
    }
}

extension View {
    /// The panel outline of this look, if it has one (no-op in looks without borders).
    func skinOutline(_ color: Color? = nil, radius: CGFloat = 0) -> some View {
        overlay {
            if let b = Theme.skin.panelBorder {
                RoundedRectangle(cornerRadius: Theme.corner(radius), style: .continuous)
                    .strokeBorder(color ?? Color(hex: b), lineWidth: Theme.skin.panelBorderWidth)
            }
        }
    }

    /// Outline of a field or control, if this look draws one.
    func fieldOutline() -> some View {
        overlay {
            if let b = Theme.skin.fieldBorder {
                PillShape().strokeBorder(Color(hex: b), lineWidth: Theme.skin.fieldBorderWidth)
            }
        }
    }
}

// MARK: - Surfaces

/// The background of a panel: filled, outlined, with a hard shadow, embossed, or just a rule.
struct PanelSurface: View {
    var radius: CGFloat
    var fill: Color
    var hero = false

    var body: some View {
        let s = Theme.skin
        let shape = RoundedRectangle(cornerRadius: Theme.corner(radius), style: .continuous)
        switch s.panelKind {
        case .ruled:
            Rectangle().fill(.clear)
                .overlay(alignment: .top) {
                    Rectangle().fill(hero ? Theme.text : Theme.line).frame(height: hero ? 3 : s.ruleWidth)
                }
        case .filled:
            shape.fill(hero && !s.heroFilled ? Theme.tile : fill)
                .overlay {
                    if let b = s.panelBorder { shape.strokeBorder(Color(hex: b), lineWidth: s.panelBorderWidth) }
                }
                .overlay {
                    if s.panelEmboss {
                        shape.strokeBorder(LinearGradient(colors: [Color(hex: 0x3A3A33), .clear],
                                                          startPoint: .top, endPoint: .center), lineWidth: 1)
                    }
                }
                .background {
                    if s.panelShadow > 0 {
                        shape.fill(Color(hex: s.panelBorder ?? 0x000000)).offset(x: s.panelShadow, y: s.panelShadow)
                    } else if s.panelEmboss {
                        shape.fill(Color(hex: 0x0A0A09)).offset(y: 2)
                    }
                }
        }
    }
}

/// A panel. `hero` marks the one coloured block per screen: filled in looks with a filled hero,
/// a plain panel in the others.
struct Tile<Content: View>: View {
    var padding: CGFloat
    var fill: Color
    var hero: Bool
    let content: Content

    init(padding: CGFloat = 20, fill: Color = Theme.tile, hero: Bool = false, @ViewBuilder content: () -> Content) {
        self.padding = padding
        self.fill = fill
        self.hero = hero
        self.content = content()
    }

    var body: some View {
        let s = Theme.skin
        let pad = min(padding, s.tilePadMax)
        content
            .padding(.horizontal, s.panelKind == .ruled ? 0 : pad)
            .padding(.vertical, s.panelKind == .ruled ? min(pad, 14) + 4 : pad)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(PanelSurface(radius: 22, fill: fill, hero: hero))
    }
}

extension View {
    /// The coloured header block inside a panel (the severity block on a finding).
    func heroSurface(_ fill: Color, radius: CGFloat = 18) -> some View {
        let s = Theme.skin
        let shape = RoundedRectangle(cornerRadius: Theme.corner(radius), style: .continuous)
        return background(shape.fill(s.heroFilled ? fill : Theme.well))
            .overlay {
                if s.heroFilled {
                    if let b = s.panelBorder { shape.strokeBorder(Color(hex: b), lineWidth: s.panelBorderWidth) }
                } else if s.panelKind == .filled {
                    shape.strokeBorder(Theme.line, lineWidth: 1)
                } else {
                    Rectangle().fill(Theme.text).frame(height: 2).frame(maxHeight: .infinity, alignment: .top)
                }
            }
    }
}

/// The label on a hero block. A dark capsule with coloured text, a marker and text in the status
/// colour, bare coloured text, or a white sticker, depending on the look.
struct HeroBadge: View {
    let text: String
    let color: Color
    var ink: Color = Theme.accentInk
    var size: CGFloat = 13

    var body: some View {
        switch Theme.skin.badge {
        case .chip:
            Text(text)
                .font(.ui(size, 600))
                .foregroundStyle(color)
                .padding(.horizontal, 12)
                .padding(.vertical, 5)
                .background(Capsule().fill(ink))
        case .marker:
            HStack(spacing: 7) {
                DotShape().fill(color).frame(width: 8, height: 8)
                Text(text).font(.label(size, 700)).foregroundStyle(color).labelCase(tracking: 2)
            }
        case .plain:
            Text(text).font(.ui(size, 800)).foregroundStyle(color)
        case .sticker:
            Text(text)
                .font(.tag(size - 1, 700))
                .textCase(.uppercase)
                .foregroundStyle(Color(hex: 0x111111))
                .padding(.horizontal, 12)
                .padding(.vertical, 3)
                .background(Capsule().fill(.white))
                .overlay(Capsule().strokeBorder(Color(hex: 0x111111), lineWidth: 2))
        }
    }
}

struct TileHeader<Trailing: View>: View {
    let title: String
    var caption: String?
    let trailing: Trailing

    init(_ title: String, caption: String? = nil, @ViewBuilder trailing: () -> Trailing) {
        self.title = title
        self.caption = caption
        self.trailing = trailing()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.ui(14, 600)).foregroundStyle(Theme.text).labelCase(tracking: 1.5, control: true)
                    if let caption {
                        Text(caption).font(.ui(12.5)).foregroundStyle(Theme.text3)
                    }
                }
                Spacer(minLength: 8)
                trailing
            }
            if Theme.skin.rows != .slab { RuleLine(style: .solid, color: Theme.line) }
        }
    }
}

extension TileHeader where Trailing == EmptyView {
    init(_ title: String, caption: String? = nil) {
        self.init(title, caption: caption) { EmptyView() }
    }
}

/// A row inside a tile: a lighter slab with a hover state, or a plain row with a rule under it.
struct InsetRow: ViewModifier {
    var selected = false
    var padding = EdgeInsets(top: 11, leading: 14, bottom: 11, trailing: 14)
    @State private var hover = false

    func body(content: Content) -> some View {
        let s = Theme.skin
        if s.rows == .slab {
            content
                .padding(padding)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(selected ? Theme.insetHover : hover ? Theme.insetHover.opacity(0.7) : Theme.inset))
                .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(selected ? Theme.text.opacity(0.35) : .clear, lineWidth: 1))
                .contentShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                .onHover { hover = $0 }
        } else {
            // No slab: a rule under each row, a tint on hover, and an accent bar on the selected one.
            content
                .padding(EdgeInsets(top: max(6, padding.top * 0.7), leading: max(8, padding.leading * 0.75),
                                    bottom: max(6, padding.bottom * 0.7), trailing: max(8, padding.trailing * 0.75)))
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(selected ? Theme.insetHover : hover ? Theme.inset : .clear)
                .overlay(alignment: .bottom) { RuleLine() }
                .overlay(alignment: .leading) {
                    if selected { Rectangle().fill(Theme.accentText).frame(width: 2) }
                }
                .contentShape(Rectangle())
                .onHover { hover = $0 }
        }
    }
}

extension View {
    func insetRow(selected: Bool = false, padding: EdgeInsets = EdgeInsets(top: 11, leading: 14, bottom: 11, trailing: 14)) -> some View {
        modifier(InsetRow(selected: selected, padding: padding))
    }
}

// MARK: - Small components

struct Dot: View {
    let color: Color
    var size: CGFloat = 8
    var body: some View { DotShape().fill(color).frame(width: size, height: size) }
}

struct SelectBox: View {
    let on: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            RoundedRectangle(cornerRadius: Theme.corner(5), style: .continuous)
                .fill(on ? Theme.accent : Color.clear)
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.corner(5), style: .continuous)
                        .strokeBorder(on ? Theme.accent : Theme.line, lineWidth: 1.5))
                .overlay(
                    Image(systemName: "checkmark")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(Theme.onFill)
                        .opacity(on ? 1 : 0))
                .frame(width: 16, height: 16)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(on ? "Deselect finding" : "Select finding")
    }
}

struct Pill: View {
    let text: String
    var color: Color = Theme.text2
    var fill: Color = Theme.inset

    init(_ text: String, color: Color = Theme.text2, fill: Color = Theme.inset) {
        self.text = text
        self.color = color
        self.fill = fill
    }

    /// Sticker pills use the bright version of the status colour.
    private var sticker: Color {
        // Neo-Brutal uses near-black as its accent text; a black sticker with
        // black ink is unreadable, so fall back to the bright accent fill.
        if color == Theme.accentText { return Theme.accent }
        if color == Theme.amber { return Theme.warnFill }
        if color == Theme.text2 || color == Theme.text3 { return Theme.tile }
        return color
    }

    var body: some View {
        let s = Theme.skin
        let label = Text(text).font(.tag(11.5, 500)).labelCase()
        switch s.pills {
        case .tinted:
            label.foregroundStyle(color)
                .padding(.horizontal, 9).padding(.vertical, 3.5)
                .background(CapShape(radius: min(s.pillRadius, 6)).fill(fill))
                .fixedSize()
        case .outlined:
            label.foregroundStyle(color)
                .padding(.horizontal, 9).padding(.vertical, 3.5)
                .overlay(Rectangle().strokeBorder(color.opacity(0.6), lineWidth: 1))
                .fixedSize()
        case .sticker:
            label.foregroundStyle(Color(hex: 0x111111))
                .padding(.horizontal, 7).padding(.vertical, 1.5)
                .background(CapShape(radius: 6).fill(sticker))
                .overlay(CapShape(radius: 6).strokeBorder(Color(hex: 0x111111), lineWidth: 2))
                .fixedSize()
        }
    }
}

struct SeverityLabel: View {
    let severity: Severity
    var body: some View {
        HStack(spacing: 6) {
            Dot(color: severity.color, size: 7)
            Text(severity.label).font(.tag(12, 500)).foregroundStyle(severity.color).labelCase()
        }
        .fixedSize()
    }
}

struct PathText: View {
    let path: String
    var size: CGFloat = 11

    init(_ path: String, size: CGFloat = 11) {
        self.path = path
        self.size = size
    }

    var body: some View {
        Text(Fmt.tilde(path))
            .font(.mono(size))
            .foregroundStyle(Theme.text3)
            .lineLimit(1)
            .truncationMode(.middle)
            .help(path)
    }
}

struct Spinner: View {
    var color: Color = Theme.text
    var size: CGFloat = 12
    @State private var spin = false

    var body: some View {
        Circle()
            .trim(from: 0.15, to: 0.85)
            .stroke(color, style: StrokeStyle(lineWidth: 1.8, lineCap: .round))
            .frame(width: size, height: size)
            .rotationEffect(.degrees(spin ? 360 : 0))
            .onAppear {
                withAnimation(.linear(duration: 0.9).repeatForever(autoreverses: false)) { spin = true }
            }
    }
}

struct BrandMark: View {
    var size: CGFloat = 40

    var body: some View {
        RoundedRectangle(cornerRadius: Theme.corner(size * 0.32), style: .continuous)
            .fill(Theme.accent)
            .frame(width: size, height: size)
            .overlay(ShieldShape().fill(Theme.accentInk).frame(width: size * 0.38, height: size * 0.44))
            .overlay {
                if Theme.skin.panelShadow > 0 {
                    RoundedRectangle(cornerRadius: Theme.corner(size * 0.32), style: .continuous)
                        .strokeBorder(Color(hex: 0x111111), lineWidth: 2)
                }
            }
    }
}

struct ShieldShape: Shape {
    func path(in r: CGRect) -> Path {
        let w = r.width, h = r.height
        var p = Path()
        p.move(to: CGPoint(x: r.midX, y: r.minY))
        p.addLine(to: CGPoint(x: r.maxX, y: r.minY + h * 0.16))
        p.addLine(to: CGPoint(x: r.maxX, y: r.minY + h * 0.5))
        p.addCurve(to: CGPoint(x: r.midX, y: r.maxY),
                   control1: CGPoint(x: r.maxX, y: r.minY + h * 0.78),
                   control2: CGPoint(x: r.midX + w * 0.3, y: r.maxY - h * 0.06))
        p.addCurve(to: CGPoint(x: r.minX, y: r.minY + h * 0.5),
                   control1: CGPoint(x: r.midX - w * 0.3, y: r.maxY - h * 0.06),
                   control2: CGPoint(x: r.minX, y: r.minY + h * 0.78))
        p.addLine(to: CGPoint(x: r.minX, y: r.minY + h * 0.16))
        p.closeSubpath()
        return p
    }
}

struct EmptyNote: View {
    let symbol: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: symbol).font(.system(size: 20)).foregroundStyle(Theme.text3).padding(.bottom, 4)
            Text(title).font(.ui(14, 600)).foregroundStyle(Theme.text)
            Text(message).font(.ui(12.5)).foregroundStyle(Theme.text2).multilineTextAlignment(.center)
                .frame(maxWidth: 360)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 30)
    }
}

/// App icon for an executable inside a bundle, or a neutral glyph.
struct ProgramIcon: View {
    let path: String
    var size: CGFloat = 30

    var body: some View {
        if let image = IconCache.icon(for: path) {
            Image(nsImage: image).resizable().interpolation(.high).frame(width: size, height: size)
        } else {
            Image(systemName: "terminal")
                .font(.system(size: size * 0.4))
                .foregroundStyle(Theme.text2)
                .frame(width: size, height: size)
                .background(RoundedRectangle(cornerRadius: Theme.corner(size * 0.3), style: .continuous).fill(Theme.well))
                .skinOutline(Theme.line, radius: size * 0.3)
        }
    }
}

enum IconCache {
    private static var cache: [String: NSImage] = [:]
    private static var misses: Set<String> = []

    static func icon(for path: String) -> NSImage? {
        guard let bundle = Fmt.bundlePath(path) else { return nil }
        if let hit = cache[bundle] { return hit }
        if misses.contains(bundle) { return nil }
        guard FileManager.default.fileExists(atPath: bundle) else {
            misses.insert(bundle)
            return nil
        }
        let image = NSWorkspace.shared.icon(forFile: bundle)
        cache[bundle] = image
        return image
    }
}

struct SignatureLabel: View {
    let signature: String

    var body: some View {
        let info = SignatureInfo(signature)
        HStack(spacing: 6) {
            Image(systemName: info.icon).font(.system(size: 10.5, weight: .semibold)).foregroundStyle(info.iconColor)
            Text(info.label).font(.ui(12.5)).foregroundStyle(info.textColor).lineLimit(1)
        }
        .help(info.detail)
    }
}

struct SignatureInfo {
    let label: String
    let detail: String
    let icon: String
    let iconColor: Color
    let textColor: Color

    init(_ s: String) {
        if s == "apple" {
            (label, detail, icon, iconColor, textColor) = ("Apple", "Signed by Apple", "checkmark.seal.fill", Theme.green, Theme.text2)
        } else if s.hasPrefix("developer: ") {
            var name = String(s.dropFirst("developer: ".count))
            name = name.replacingOccurrences(of: "Developer ID Application: ", with: "")
            if let paren = name.range(of: " (", options: .backwards) { name = String(name[..<paren.lowerBound]) }
            let short = name.count > 24 ? String(name.prefix(22)).trimmingCharacters(in: .whitespaces) + "…" : name
            (label, detail, icon, iconColor, textColor) = (short, "Verified developer: \(name)", "checkmark.seal.fill", Theme.green, Theme.text2)
        } else if s == "adhoc" {
            (label, detail, icon, iconColor, textColor) = ("Self-signed", "Signed by whoever built it, not a verified developer",
                                                           "signature", Theme.blue, Theme.blue)
        } else if s == "unsigned" {
            (label, detail, icon, iconColor, textColor) = ("Unsigned", "Nobody vouches for this program",
                                                           "xmark.seal.fill", Theme.red, Theme.red)
        } else {
            (label, detail, icon, iconColor, textColor) = ("Unknown", "Signature couldn't be read", "questionmark.circle", Theme.text3, Theme.text3)
        }
    }
}

struct SegmentBar: View {
    let colors: [Color]
    var height: CGFloat = 6

    var body: some View {
        HStack(spacing: 3) {
            ForEach(Array(colors.enumerated()), id: \.offset) { _, c in
                CapShape(radius: Theme.skin.barRadius).fill(c).frame(height: Theme.ops ? max(height, 12) : height)
            }
        }
    }
}

struct Spark: View {
    let values: [Int]
    var color: Color = Theme.sparkBase
    var highlight: Color? = nil
    var height: CGFloat = 44

    var body: some View {
        let peak = max(1, values.max() ?? 1)
        HStack(alignment: .bottom, spacing: 3) {
            ForEach(Array(values.enumerated()), id: \.offset) { i, v in
                RoundedRectangle(cornerRadius: Theme.corner(2))
                    .fill(i == values.count - 1 ? (highlight ?? color) : color)
                    .frame(width: 5, height: max(4, height * CGFloat(v) / CGFloat(peak)))
            }
        }
        .frame(height: height, alignment: .bottom)
    }
}

/// A stat tile: label, big figure, optional caption and accessory.
struct StatTile<Accessory: View>: View {
    let label: String
    let value: String
    var caption: String? = nil
    var captionColor: Color = Theme.text2
    var action: (() -> Void)? = nil
    let accessory: Accessory
    @State private var hover = false

    init(_ label: String, value: String, caption: String? = nil, captionColor: Color = Theme.text2,
         action: (() -> Void)? = nil, @ViewBuilder accessory: () -> Accessory) {
        self.label = label
        self.value = value
        self.caption = caption
        self.captionColor = captionColor
        self.action = action
        self.accessory = accessory()
    }

    var body: some View {
        Tile(fill: hover && action != nil ? Theme.insetHover.opacity(0.55) : Theme.tile) {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .firstTextBaseline) {
                    Text(label).font(.label(13, 400)).foregroundStyle(Theme.text2).labelCase(tracking: 1.5)
                    Spacer()
                    if let caption { Text(caption).font(.label(12, 500)).foregroundStyle(captionColor).labelCase() }
                }
                Spacer(minLength: 14)
                HStack(alignment: .bottom, spacing: 12) {
                    Text(value).font(.figure(44)).foregroundStyle(Theme.text).lineLimit(1)
                        .minimumScaleFactor(0.6)
                    Spacer(minLength: 0)
                    accessory
                }
            }
        }
        .contentShape(Rectangle())
        .onHover { hover = $0 }
        .onTapGesture { action?() }
    }
}

extension StatTile where Accessory == EmptyView {
    init(_ label: String, value: String, caption: String? = nil, captionColor: Color = Theme.text2,
         action: (() -> Void)? = nil) {
        self.init(label, value: value, caption: caption, captionColor: captionColor, action: action) { EmptyView() }
    }
}

// MARK: - Controls

enum ButtonRole { case primary, accent, ghost }

/// How a button is drawn in the current look.
struct ButtonSpec {
    var fill: Color
    var hover: Color
    var ink: Color
    var stroke: Color? = nil
    var strokeWidth: CGFloat = 1
    var edge: Color? = nil          // keycap: a darker lip under the key
    var shadow: Color? = nil        // brutal: a hard offset shadow

    static func make(_ role: ButtonRole) -> ButtonSpec {
        let ink = Color(hex: 0x111111)
        switch (Theme.look, role) {
        case (.bento, .primary): return ButtonSpec(fill: Theme.text, hover: .white, ink: Theme.bg)
        case (.bento, .accent): return ButtonSpec(fill: Theme.accent, hover: Theme.accentHover, ink: Theme.accentInk)
        case (.bento, .ghost): return ButtonSpec(fill: Color(hex: 0x323235), hover: Color(hex: 0x3D3D41), ink: Theme.text)

        case (.fieldops, .ghost): return ButtonSpec(fill: .clear, hover: Theme.insetHover, ink: Theme.text, stroke: Theme.edge)
        case (.fieldops, _): return ButtonSpec(fill: Theme.accent, hover: Theme.accentHover, ink: Theme.accentInk, stroke: Theme.accent)

        case (.graphite, .primary): return ButtonSpec(fill: Color(hex: 0xECEDEF), hover: .white, ink: Color(hex: 0x0C0D0F))
        case (.graphite, .accent): return ButtonSpec(fill: Theme.accent, hover: Theme.accentHover, ink: Theme.accentInk)
        case (.graphite, .ghost): return ButtonSpec(fill: .clear, hover: Theme.insetHover, ink: Theme.text, stroke: Theme.edge)

        case (.dotmatrix, .ghost): return ButtonSpec(fill: .clear, hover: Theme.inset, ink: Theme.text, stroke: Theme.edge)
        case (.dotmatrix, _): return ButtonSpec(fill: .white, hover: Color(hex: 0xE4E4E4), ink: .black)

        case (.swiss, .primary): return ButtonSpec(fill: Theme.text, hover: .white, ink: Theme.bg)
        case (.swiss, .accent): return ButtonSpec(fill: Theme.accent, hover: Theme.accentHover, ink: Theme.accentInk)
        case (.swiss, .ghost): return ButtonSpec(fill: .clear, hover: Theme.inset, ink: Theme.text, stroke: Theme.edge)

        case (.hardware, .primary):
            return ButtonSpec(fill: Color(hex: 0xE7E5DE), hover: Color(hex: 0xF2F0E9), ink: Color(hex: 0x1A1A18), edge: Color(hex: 0xA9A79F))
        case (.hardware, .accent):
            return ButtonSpec(fill: Theme.accent, hover: Theme.accentHover, ink: Theme.accentInk, edge: Color(hex: 0xB5410F))
        case (.hardware, .ghost):
            return ButtonSpec(fill: Theme.inset, hover: Theme.insetHover, ink: Theme.text, edge: Color(hex: 0x141413))

        case (.brutal, .primary):
            return ButtonSpec(fill: ink, hover: Color(hex: 0x2C2C2A), ink: .white, stroke: ink, strokeWidth: 2, shadow: ink)
        case (.brutal, .accent):
            return ButtonSpec(fill: Theme.accent, hover: Theme.accentHover, ink: ink, stroke: ink, strokeWidth: 2, shadow: ink)
        case (.brutal, .ghost):
            return ButtonSpec(fill: .white, hover: Theme.insetHover, ink: ink, stroke: ink, strokeWidth: 2, shadow: ink)
        }
    }
}

private struct PillButtonBody: View {
    let configuration: ButtonStyleConfiguration
    let spec: ButtonSpec
    var compact = false
    @Environment(\.isEnabled) private var enabled
    @State private var hover = false

    var body: some View {
        let lip: CGFloat = spec.edge != nil ? 3 : 0
        let lift: CGFloat = spec.shadow != nil ? 3 : 0
        let pressed = configuration.isPressed
        configuration.label
            .font(.ui(compact ? 12 : 13, Theme.skin.capsControls ? 700 : 600))
            .labelCase(tracking: 0.8, control: true)
            .foregroundStyle(spec.ink)
            .padding(.horizontal, compact ? 12 : 18)
            .padding(.vertical, compact ? 6 : 10)
            .padding(.bottom, lip)
            .background {
                ZStack(alignment: .top) {
                    if let edge = spec.edge { PillShape().fill(edge) }
                    if let shadow = spec.shadow, !pressed { PillShape().fill(shadow).offset(x: lift, y: lift) }
                    PillShape().fill(hover ? spec.hover : spec.fill).padding(.bottom, lip)
                }
            }
            .overlay(PillShape().strokeBorder(spec.stroke ?? .clear, lineWidth: spec.strokeWidth).padding(.bottom, lip))
            .offset(x: pressed ? lift : 0, y: pressed ? max(lift, lip > 0 ? 2 : 0) : 0)
            .scaleEffect(pressed && lift == 0 && lip == 0 ? 0.97 : 1)
            .opacity(enabled ? 1 : 0.45)
            .animation(.easeOut(duration: 0.12), value: pressed)
            .contentShape(PillShape())
            .focusEffectDisabled()
            .onHover { hover = $0 }
    }
}

/// The default primary action.
struct LightButtonStyle: ButtonStyle {
    var compact = false
    func makeBody(configuration: Configuration) -> some View {
        PillButtonBody(configuration: configuration, spec: .make(.primary), compact: compact)
    }
}

/// The brand action (Check a link, Scan).
struct CoralButtonStyle: ButtonStyle {
    var compact = false
    func makeBody(configuration: Configuration) -> some View {
        PillButtonBody(configuration: configuration, spec: .make(.accent), compact: compact)
    }
}

/// Secondary actions.
struct GhostButtonStyle: ButtonStyle {
    var compact = false
    func makeBody(configuration: Configuration) -> some View {
        PillButtonBody(configuration: configuration, spec: .make(.ghost), compact: compact)
    }
}

/// Buttons that sit on a hero block.
struct HeroButtonStyle: ButtonStyle {
    let level: ThreatLevel
    var outline = false
    func makeBody(configuration: Configuration) -> some View {
        let spec: ButtonSpec
        switch Theme.look {
        case .bento:
            spec = ButtonSpec(fill: outline ? .clear : level.heroInk,
                              hover: outline ? level.heroInk.opacity(0.08) : level.heroInk.opacity(0.85),
                              ink: outline ? level.heroInk : level.hero,
                              stroke: outline ? level.heroInk : nil, strokeWidth: 2)
        case .fieldops:
            spec = ButtonSpec(fill: .clear, hover: Theme.insetHover, ink: outline ? Theme.text : level.hero,
                              stroke: outline ? Theme.edge : level.hero)
        case .hardware:
            spec = .make(outline ? .primary : .accent)
        default:
            spec = .make(outline ? .ghost : .primary)
        }
        return PillButtonBody(configuration: configuration, spec: spec)
    }
}

struct TextLinkStyle: ButtonStyle {
    var color: Color = Theme.accentText
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.ui(12.5, 500))
            .labelCase(tracking: 0.8, control: true)
            .foregroundStyle(color.opacity(configuration.isPressed ? 0.7 : 1))
            .contentShape(Rectangle())
    }
}

struct RoundIconButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(Theme.text2)
            .frame(width: 32, height: 32)
            .background(RoundShape().fill(configuration.isPressed ? Theme.insetHover : Theme.inset))
            .overlay {
                if let b = Theme.skin.fieldBorder {
                    RoundShape().strokeBorder(Color(hex: b), lineWidth: Theme.skin.fieldBorderWidth)
                }
            }
            .contentShape(RoundShape())
    }
}

struct SwitchStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        let on = configuration.isOn
        HStack(spacing: 14) {
            configuration.label
            Spacer(minLength: 12)
            Group {
                if Theme.skin.switchBlock {
                    // [ ON ] / [ OFF ]: a bordered block that fills with the accent when on.
                    let border = Theme.ops ? (on ? Theme.accent : Theme.edge) : Theme.edge
                    Text(on ? "ON" : "OFF")
                        .font(.tag(11.5, 700)).tracking(1)
                        .foregroundStyle(on ? Theme.accentInk : Theme.text3)
                        .frame(width: 46, height: 24)
                        .background(CapShape(radius: Theme.skin.pillRadius).fill(on ? Theme.accent : .clear))
                        .overlay(CapShape(radius: Theme.skin.pillRadius)
                            .strokeBorder(border, lineWidth: Theme.skin.fieldBorderWidth))
                } else {
                    let trackOn: Color = (Theme.look == .graphite || Theme.look == .hardware) ? Theme.accent : Theme.text
                    let knobOn: Color = (Theme.look == .graphite || Theme.look == .hardware) ? Theme.accentInk : Theme.bg
                    ZStack(alignment: on ? .trailing : .leading) {
                        Capsule().fill(on ? trackOn : Theme.edge.opacity(Theme.look == .bento ? 1 : 0.8))
                            .frame(width: 40, height: 24)
                        Circle().fill(on ? knobOn : Theme.text3).frame(width: 18, height: 18).padding(3)
                    }
                }
            }
            .contentShape(Rectangle())
            .onTapGesture {
                withAnimation(.spring(response: 0.25, dampingFraction: 0.8)) { configuration.isOn.toggle() }
            }
        }
    }
}

struct Segmented<T: Hashable>: View {
    let options: [(value: T, label: String)]
    @Binding var selection: T
    @Namespace private var ns

    var body: some View {
        let on = ButtonSpec.make(.primary)
        let accent = Theme.ops ? ButtonSpec.make(.accent) : on
        HStack(spacing: Theme.skin.pillRadius < 20 ? 0 : 2) {
            ForEach(Array(options.enumerated()), id: \.offset) { _, option in
                let selected = option.value == selection
                Text(option.label)
                    .font(.ui(12.5, selected ? 600 : 500))
                    .labelCase(tracking: 0.8, control: true)
                    .foregroundStyle(selected ? accent.ink : Theme.text2)
                    .padding(.horizontal, 13)
                    .padding(.vertical, 7)
                    .background {
                        if selected {
                            PillShape().fill(accent.fill).matchedGeometryEffect(id: "seg", in: ns)
                        }
                    }
                    .contentShape(PillShape())
                    .onTapGesture {
                        withAnimation(.spring(response: 0.28, dampingFraction: 0.85)) { selection = option.value }
                    }
            }
        }
        .padding(Theme.ops ? 2 : 3)
        .background(PillShape().fill(Theme.inset))
        .fieldOutline()
        .fixedSize()
    }
}

struct SearchField: View {
    @Binding var text: String
    var placeholder: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.text3)
            TextField("", text: $text, prompt: Text(placeholder).foregroundStyle(Theme.text3))
                .textFieldStyle(.plain)
                .font(.ui(13))
                .foregroundStyle(Theme.text)
            if !text.isEmpty {
                Button { text = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain)
                    .foregroundStyle(Theme.text3)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .background(PillShape().fill(Theme.inset))
        .fieldOutline()
    }
}

/// A themed dropdown: a small field plus a dark list, instead of the system menu.
struct ThemeMenu<Item: Hashable>: View {
    let placeholder: String
    let items: [Item]
    let title: (Item) -> String
    @Binding var selection: Item?

    @State private var open = ProcessInfo.processInfo.environment["SAFEGUARD_OPEN_MENU"] == "1"

    var body: some View {
        Button { open = true } label: {
            HStack(spacing: 6) {
                Text(selection.map(title) ?? placeholder)
                    .font(.ui(12, 500)).foregroundStyle(Theme.text).lineLimit(1)
                Image(systemName: "chevron.down")
                    .font(.system(size: 9, weight: .semibold)).foregroundStyle(Theme.text3)
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(CapShape(radius: 8).fill(Theme.inset))
            .overlay(CapShape(radius: 8).strokeBorder(Theme.line, lineWidth: 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .fixedSize()
        .popover(isPresented: $open, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 2) {
                row(placeholder, selected: selection == nil) {
                    selection = nil
                    open = false
                }
                ForEach(items, id: \.self) { item in
                    row(title(item), selected: selection == item) {
                        selection = item
                        open = false
                    }
                }
            }
            .padding(6)
            .frame(minWidth: 170)
            .background(Theme.tile)
            .presentationBackground(Theme.tile)
        }
    }

    private func row(_ text: String, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Text(text).font(.ui(12.5, selected ? 600 : 400)).foregroundStyle(Theme.text)
                Spacer(minLength: 12)
                if selected {
                    Image(systemName: "checkmark").font(.system(size: 9, weight: .bold))
                        .foregroundStyle(Theme.text2)
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(CapShape(radius: 7).fill(selected ? Theme.inset : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
